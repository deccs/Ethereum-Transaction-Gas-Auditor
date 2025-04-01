# transactions/views.py

import requests
import json
import logging
import io
import datetime
import decimal
import os
import re

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings

from google.cloud import bigquery, exceptions
from google.cloud.bigquery import LoadJobConfig, SourceFormat, WriteDisposition

# --- Configuration & Logging ---
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
GCP_BLOCKCHAIN_RPC_ENDPOINT = settings.GCP_BLOCKCHAIN_RPC_ENDPOINT
PROJECT_ID = settings.PROJECT_ID
DATASET_ID = settings.DATASET_ID
TABLE_ID = settings.TABLE_ID
SERVICE_ACCOUNT_JSON = settings.SERVICE_ACCOUNT_JSON  # Path or JSON string

SERVICE_ACCOUNT_JSON_PATH = None
SERVICE_ACCOUNT_JSON_CONTENT = None
SERVICE_ACCOUNT_VALID = False
if SERVICE_ACCOUNT_JSON:
    if os.path.isfile(SERVICE_ACCOUNT_JSON):
        SERVICE_ACCOUNT_JSON_PATH = SERVICE_ACCOUNT_JSON
        SERVICE_ACCOUNT_VALID = True
        logging.info(f"Using service account JSON file: {SERVICE_ACCOUNT_JSON_PATH}")
    else:
        try:
            json.loads(SERVICE_ACCOUNT_JSON)
            SERVICE_ACCOUNT_JSON_CONTENT = SERVICE_ACCOUNT_JSON
            SERVICE_ACCOUNT_VALID = True
            logging.info(
                "Using service account JSON content from environment variable."
            )
        except json.JSONDecodeError:
            logging.error(
                "SERVICE_ACCOUNT_JSON is set but is not a valid file path or JSON string."
            )
else:
    logging.error("SERVICE_ACCOUNT_JSON environment variable is not set.")

# --- Helper Functions ---


def _safe_hex_to_int(value):
    """Safely converts hex (or int/string representation) to integer."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        try:
            return int(value)  # Handle potential direct numeric types
        except (ValueError, TypeError):
            return None
    try:
        if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
            return int(value)
        hex_val = value if value.startswith("0x") else f"0x{value}"
        return int(hex_val, 16)
    except (ValueError, TypeError):
        return None


def _safe_hex_to_numeric(value):
    """Safely converts hex (or numeric string/int) to Decimal for BigQuery NUMERIC."""
    if value is None:
        return None
    int_val = None
    try:
        if isinstance(value, decimal.Decimal):
            return value
        if isinstance(value, (int, float)):
            int_val = int(value)
        elif isinstance(value, str):
            if value.startswith("0x"):
                int_val = int(value, 16)
            elif value.replace(".", "", 1).isdigit() or (
                value.startswith("-") and value[1:].replace(".", "", 1).isdigit()
            ):
                try:
                    # Use context for precision if needed, default is fine here
                    return decimal.Decimal(value)
                except decimal.InvalidOperation:
                    try:
                        int_val = int(float(value))
                    except ValueError:
                        return None
            else:
                return None
        else:
            return None
        return decimal.Decimal(int_val) if int_val is not None else None
    except (ValueError, TypeError, decimal.InvalidOperation):
        return None


def format_address(addr):
    """Helper to shorten address for display in logs/suggestions."""
    if isinstance(addr, str) and len(addr) >= 42 and addr.startswith("0x"):
        return f"{addr[:6]}...{addr[-4:]}"
    return addr or "N/A"


# --- RPC Helper ---
def _make_rpc_call(method, params):
    """Generic function to make JSON-RPC calls."""
    if not GCP_BLOCKCHAIN_RPC_ENDPOINT:
        logging.error("GCP_BLOCKCHAIN_RPC_ENDPOINT is not configured.")
        return None, "RPC endpoint not configured"

    url = GCP_BLOCKCHAIN_RPC_ENDPOINT
    headers = {"Content-Type": "application/json"}
    data = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    try:
        response = requests.post(
            url, headers=headers, data=json.dumps(data), timeout=120
        )
        response.raise_for_status()
        result = response.json()

        if "error" in result:
            rpc_error = result["error"]
            rpc_error_msg = rpc_error.get("message", "Unknown RPC error")
            rpc_error_code = rpc_error.get("code", None)
            logging.error(
                f"RPC Error for {method} (Code: {rpc_error_code}): {rpc_error_msg}"
            )
            error_lower = rpc_error_msg.lower()
            if "method not found" in error_lower or "module not found" in error_lower:
                return None, f"RPC method '{method}' not supported by the endpoint."
            if (
                "header not found" in error_lower
                or "transaction not found" in error_lower
            ):
                return None, "Transaction or related block not found by RPC endpoint."
            if "execution timeout" in error_lower or "timed out" in error_lower:
                return (
                    None,
                    f"Trace generation timed out on endpoint for method {method}.",
                )
            return None, f"RPC Error: {rpc_error_msg}"
        return result.get("result"), None

    except requests.exceptions.Timeout:
        logging.error(f"Request timed out for method {method} (120s)")
        return None, "RPC request timed out"
    except requests.exceptions.HTTPError as http_err:
        error_detail = f"Request failed: {http_err}"
        try:
            error_json = response.json()
            if "error" in error_json and "message" in error_json["error"]:
                error_detail = f"RPC Endpoint Error: {error_json['error']['message']}"
        except (json.JSONDecodeError, AttributeError):
            pass  # Keep the original HTTP error detail
        logging.error(
            f"HTTP error for {method}: {error_detail} - Response: {response.text[:500]}"
        )
        return None, error_detail
    except requests.exceptions.RequestException as e:
        logging.error(f"Network or request error for {method}: {e}")
        return None, f"Network error connecting to RPC: {e}"
    except json.JSONDecodeError:
        response_text = getattr(response, "text", "N/A")[:500]
        logging.error(f"JSON decode error for {method}. Response: {response_text}")
        return None, "Failed to decode RPC response"


# --- Basic Transaction Data Fetching ---
def get_transaction_details(transaction_hash):
    result, error = _make_rpc_call("eth_getTransactionByHash", [transaction_hash])
    if error:
        logging.error(f"Failed to get tx details for {transaction_hash}: {error}")
    return result if result else None


def get_transaction_receipt(transaction_hash):
    result, error = _make_rpc_call("eth_getTransactionReceipt", [transaction_hash])
    if error:
        logging.error(f"Failed to get tx receipt for {transaction_hash}: {error}")
    return result if result else None


# --- Trace Fetching Functions ---
def get_call_trace(transaction_hash):
    """Fetches transaction trace using debug_traceTransaction with 'callTracer'."""
    params = [transaction_hash, {"tracer": "callTracer", "timeout": "100s"}]
    logging.info(f"Requesting callTracer trace for {transaction_hash}")
    result, error = _make_rpc_call("debug_traceTransaction", params)
    if error:
        return None, f"Failed to get simple trace (callTracer): {error}"
    elif result is None:
        logging.warning(f"callTracer returned null result for {transaction_hash}.")
        return (
            None,
            "Simple trace (callTracer) data not returned by endpoint (result was null).",
        )
    logging.info(f"Successfully received callTracer data for {transaction_hash}")
    return result, None


def get_struct_log_trace(transaction_hash):
    """Fetches transaction trace using debug_traceTransaction with default 'structLog' tracer."""
    params = [
        transaction_hash,
        {
            "enableMemory": False,
            "enableReturnData": False,
            "disableStorage": True,
            "timeout": "100s",
        },
    ]
    logging.info(f"Requesting default (structLog) trace for {transaction_hash}")
    result, error = _make_rpc_call("debug_traceTransaction", params)
    if error:
        return None, f"Failed to get detailed trace (structLog): {error}"
    elif result is None:
        logging.warning(
            f"structLog tracer returned null result for {transaction_hash}."
        )
        return (
            None,
            "Detailed trace (structLog) data not returned by endpoint (result was null).",
        )
    elif "structLogs" not in result:
        if isinstance(result, dict) and "error" in result:
            err_msg = result["error"].get(
                "message", "Unknown error in trace result object"
            )
            logging.error(
                f"Trace result object contained an error for {transaction_hash}: {err_msg}"
            )
            return None, f"Trace failed internally on endpoint: {err_msg}"
        logging.warning(
            f"structLog trace result missing 'structLogs' key for {transaction_hash}. Result: {str(result)[:200]}"
        )
        return (
            None,
            "Detailed trace (structLog) data in unexpected format (missing 'structLogs').",
        )
    logging.info(f"Successfully received structLog data for {transaction_hash}")
    return result, None


# --- Trace Parsing Functions ---
def parse_call_trace(trace_data):
    """
    Parses the output of debug_traceTransaction with 'callTracer'.
    Reports the gas used by the top-level call (should match receipt)
    and provides a breakdown of internal calls with their net gas usage.
    """
    if not trace_data or not isinstance(trace_data, dict):
        return {
            # RENAMED/REPURPOSED field
            "top_level_call_gas_used": 0,
            "call_breakdown": [],
            "trace_error": None,
            "error": "Invalid call trace data format",
        }

    top_level_gas_used = 0  # Store gas from the depth 0 call
    call_breakdown = []
    trace_level_error_message = trace_data.get("error")
    parsing_error = None

    def _parse_call(call, depth=0):
        nonlocal top_level_gas_used  # Use nonlocal to modify
        gas_used_raw = call.get("gasUsed", "0x0")
        gas_used_int = 0
        try:
            gas_int_nullable = _safe_hex_to_int(gas_used_raw)
            if gas_int_nullable is None:
                raise ValueError("gasUsed conversion returned None")
            gas_used_int = gas_int_nullable
            # *** CAPTURE GAS ONLY FROM TOP-LEVEL CALL ***
            if depth == 0:
                top_level_gas_used = gas_used_int
        except (ValueError, TypeError, Exception) as e:
            logging.warning(
                f"Could not parse gasUsed '{gas_used_raw}' in callTracer call: {e}"
            )
            # Assign 0 if parsing fails, but log the error
            gas_used_int = 0

        input_str = call.get("input", "")
        output_str = call.get("output", "")
        # Shorten long data for display, handle "0x" explicitly
        input_display = (
            (input_str[:10] + "..." + input_str[-4:])
            if len(input_str) > 14
            else input_str
        )
        output_display = (
            (output_str[:10] + "..." + output_str[-4:])
            if len(output_str) > 14
            else output_str
        )
        # Ensure "0x..." becomes "0x" if that's the case
        if input_display == "0x...":
            input_display = "0x"
        if output_display == "0x...":
            output_display = "0x"

        call_info = {
            "depth": depth,
            "type": call.get("type", "UNKNOWN"),
            "from": call.get("from", ""),
            "to": call.get("to", ""),
            "input": input_display,
            "output": output_display,
            "gasUsed": gas_used_int,  # This is the NET gas used WITHIN this call frame
            "error": call.get("error"),
        }
        call_breakdown.append(call_info)
        for sub_call in call.get("calls", []):
            _parse_call(sub_call, depth + 1)

    try:
        _parse_call(trace_data)
    except Exception as e:
        logging.exception(f"Error during call trace parsing logic: {e}")
        parsing_error = f"Internal parsing failed: {e}"

    # Ensure the breakdown is sorted by appearance (usually depth-first)
    # No specific sort needed if _parse_call maintains order naturally

    return {
        # RENAMED/REPURPOSED field
        "top_level_call_gas_used": top_level_gas_used,
        "call_breakdown": call_breakdown,
        "trace_error": trace_level_error_message,
        "error": parsing_error,
    }


def parse_struct_log_trace(trace_data):
    """
    Parses structLogs for opcode frequency, expensive non-call steps, errors,
    total steps, and top-level reported gas. REMOVED misleading gas contribution sum.
    """
    if (
        not trace_data
        or not isinstance(trace_data, dict)
        or "structLogs" not in trace_data
    ):
        if isinstance(trace_data, dict) and "error" in trace_data:
            err_msg = trace_data["error"].get("message", "Unknown error in trace data")
            return {"error": f"Trace result object contained an error: {err_msg}"}
        return {"error": "Invalid or missing structLogs data received"}

    struct_logs = trace_data.get("structLogs", [])
    parsing_error_details = None
    step_index_for_error = -1  # Keep track for better error reporting

    gas_used_reported_in_trace = 0
    gas_used_raw = trace_data.get("gas", trace_data.get("gasUsed"))  # Check both keys
    if gas_used_raw is not None:
        try:
            gas_int = _safe_hex_to_int(gas_used_raw)
            if gas_int is None:
                raise ValueError("top-level gas conversion returned None")
            gas_used_reported_in_trace = gas_int
        except (ValueError, TypeError):
            logging.warning(f"Invalid format for trace top-level gas: {gas_used_raw}")
            parsing_error_details = "Invalid format for reported trace gas"

    if not struct_logs:
        logging.info("Trace has 0 structLogs.")
        return {
            "gas_reported_in_trace": gas_used_reported_in_trace,
            "opcode_frequency": {},
            "top_expensive_steps": [],
            "execution_errors": [],
            "total_steps": 0,
            "error": parsing_error_details,  # Return error if top-level gas failed
        }

    opcode_counts = {}
    expensive_steps_filtered = []
    execution_errors = []
    call_opcodes = [
        "CALL",
        "DELEGATECALL",
        "STATICCALL",
        "CALLCODE",
        "CREATE",
        "CREATE2",
    ]

    try:
        for i, step in enumerate(struct_logs):
            step_index_for_error = i  # Update current step index
            gas_cost_raw = step.get("gasCost")
            gas_cost_step = 0
            if gas_cost_raw is not None:
                # Ensure cost is non-negative integer
                cost_int = _safe_hex_to_int(gas_cost_raw)
                if cost_int is not None and cost_int >= 0:
                    gas_cost_step = cost_int

            opcode = step.get("op", "UNKNOWN")
            # Handle cases where opcode might not be a string (unlikely but safe)
            if not isinstance(opcode, str):
                opcode = "INVALID_OP_FORMAT"

            opcode_counts[opcode] = opcode_counts.get(opcode, 0) + 1

            # Track expensive steps, filtering out CALLs
            # Use callTracer for reliable call gas, structLog step cost for calls is less intuitive.
            is_call_opcode = opcode in call_opcodes
            if not is_call_opcode and gas_cost_step > 1000: # Threshold for non-call steps
                expensive_steps_filtered.append(
                    {
                        "step": i,
                        "pc": step.get("pc"),
                        "opcode": opcode,
                        "gasCost": gas_cost_step, # Cost reported at this step execution
                        "depth": step.get("depth"),
                    }
                )

            if step.get("error"):
                execution_errors.append(
                    {
                        "step": i,
                        "pc": step.get("pc"),
                        "depth": step.get("depth"),
                        "error": str(step.get("error")),  # Ensure error is string
                    }
                )

    except (ValueError, TypeError, KeyError, IndexError) as e:
        logging.exception(
            f"Error processing structLog step ~{step_index_for_error}: {e}"
        )
        parsing_error_details = f"Parsing failed at step {step_index_for_error}: {e}"
    except Exception as e:
        # Catch any other unexpected errors during loop
        logging.exception(f"Unexpected error during structLog parsing: {e}")
        parsing_error_details = f"Unexpected parsing error: {e}"

    # Sort expensive steps by cost (desc) and opcodes by frequency (desc)
    expensive_steps_filtered.sort(key=lambda item: item["gasCost"], reverse=True)
    sorted_opcode_frequency = sorted(
        opcode_counts.items(), key=lambda item: item[1], reverse=True
    )

    return {
        "gas_reported_in_trace": gas_used_reported_in_trace,
        "opcode_frequency": dict(sorted_opcode_frequency),
        "top_expensive_steps": expensive_steps_filtered[:15],  # Limit to top 15
        "execution_errors": execution_errors,
        "total_steps": len(struct_logs),
        "error": parsing_error_details,  # Include parsing error if occurred
    }


# --- Scoring and Optimization Suggestions ---
def calculate_gas_score(receipt_details, call_trace_data=None, struct_log_data=None):
    """Calculates gas efficiency score using reliable data from available traces."""
    if not receipt_details or "gasUsed" not in receipt_details:
        return 0, "Receipt unavailable or missing gasUsed"

    actual_gas_used = _safe_hex_to_int(receipt_details.get("gasUsed", "0x0"))
    if actual_gas_used is None:
        logging.error(f"Invalid gasUsed in receipt: {receipt_details.get('gasUsed')}")
        return 0, "Invalid gasUsed in receipt"

    status = _safe_hex_to_int(receipt_details.get("status"))

    # --- Early Exit for Simple Transactions ---
    if actual_gas_used <= 21000:
        if status == 0:
            return 50, "Simple transaction failed"
        # Check if input data exists (more reliable than address check)
        has_input = False
        # Check both combined details and receipt directly for input
        if transaction_details := receipt_details.get("details"):
            has_input = transaction_details.get("input", "0x") not in ["0x", None, ""]
        elif "input" in receipt_details:  # Check receipt if details missing
            has_input = receipt_details.get("input", "0x") not in ["0x", None, ""]

        if actual_gas_used == 21000 and not has_input and status == 1:
            return 100, "Standard gas for basic transfer"
        elif status == 0:
            return 40, "Failed low-gas transaction"
        else:  # Success but very low gas (e.g. simple ERC20 approve(0))
            return 95, "Very low gas usage"

    # --- Start Scoring for Complex Transactions ---
    score = 100
    reason = []  # Initialize empty list for reasons

    # --- 1. Penalty for High Absolute Gas (Adjusted Thresholds) ---
    if actual_gas_used > 750_000:
        score -= 45
        reason.append(f"Extremely high gas usage ({actual_gas_used:,})")
    elif actual_gas_used > 350_000:
        score -= 30
        reason.append(f"Very high gas usage ({actual_gas_used:,})")
    elif actual_gas_used > 150_000:
        score -= 15
        reason.append(f"High gas usage ({actual_gas_used:,})")
    elif actual_gas_used > 80_000:
        score -= 8
        reason.append(f"Moderate gas usage ({actual_gas_used:,})")

    # --- 2. Penalties/Insights from callTracer (Adjusted Thresholds) ---
    call_trace_valid = (
        call_trace_data
        and not call_trace_data.get("error")  # No parse error
        and not call_trace_data.get("trace_error")  # No execution error in trace
        and call_trace_data.get("call_breakdown")  # Has breakdown data
    )
    if call_trace_valid:
        breakdown = call_trace_data["call_breakdown"]
        internal_calls = [c for c in breakdown if c['depth'] > 0] # Exclude the top-level call itself
        num_internal_calls = len(internal_calls)
        max_depth = max(call["depth"] for call in breakdown) if breakdown else 0

        # Check for expensive internal calls (Threshold 40% of NET gas)
        expensive_internal_calls = [
            c for c in internal_calls if c.get("gasUsed", 0) > actual_gas_used * 0.40
        ]
        if expensive_internal_calls:
            score -= 15
            most_expensive = max(
                expensive_internal_calls, key=lambda c: c.get("gasUsed", 0)
            )
            percent = (
                (most_expensive.get("gasUsed", 0) / actual_gas_used) * 100
                if actual_gas_used > 0
                else 0
            )
            reason.append(
                f"Expensive internal call ({most_expensive.get('type')} to {format_address(most_expensive.get('to'))}) consumed {most_expensive.get('gasUsed',0):,} net gas ({percent:.1f}%)"
            )

        # Depth Penalties (scaled)
        if max_depth > 8:
            score -= min(15, (max_depth - 8) * 3)  # More penalty for deeper stacks
            reason.append(f"Very deep call stack (depth {max_depth})")
        elif max_depth > 4:
            score -= min(8, (max_depth - 4) * 2)
            reason.append(f"Deep call stack (depth {max_depth})")

        # Call Count Penalties (scaled)
        if num_internal_calls > 40:
            score -= min(15, (num_internal_calls - 40))  # Scale penalty
            reason.append(
                f"Extremely high number of internal calls ({num_internal_calls})"
            )
        elif num_internal_calls > 15:
            score -= min(8, (num_internal_calls - 15))
            reason.append(f"High number of internal calls ({num_internal_calls})")

        # Penalties for errors within calls (significant penalty)
        internal_call_errors = [call for call in internal_calls if call.get("error")]
        if internal_call_errors:
            score -= 25  # Heavy penalty for internal failures
            reason.append(
                f"Internal errors/reverts found in call trace ({len(internal_call_errors)} call(s))"
            )

    # --- 3. Penalties/Insights from structLog (Adjusted Thresholds & Independent Check) ---
    struct_log_valid = struct_log_data and not struct_log_data.get("error")
    if struct_log_valid:
        opcode_freq = struct_log_data.get("opcode_frequency", {})
        sstore_count = opcode_freq.get("SSTORE", 0)
        sload_count = opcode_freq.get("SLOAD", 0)

        # Storage Operation Counts (Scaled penalty)
        if sstore_count > 7:
            score -= min(12, sstore_count)  # Cap penalty slightly
            reason.append(f"High number of storage writes ({sstore_count} SSTOREs)")
        elif sstore_count >= 3:
            score -= 5
            reason.append(f"Moderate number of storage writes ({sstore_count} SSTOREs)")
        if sload_count > 35:
            score -= min(8, sload_count // 4)  # Scaled penalty
            reason.append(f"High number of storage reads ({sload_count} SLOADs)")
        elif sload_count > 15:
            score -= 3
            reason.append(f"Moderate number of storage reads ({sload_count} SLOADs)")

        # Check for execution errors (if not already penalized by callTracer)
        # structLog errors might catch things callTracer misses sometimes
        if struct_log_data.get("execution_errors"):
            if not any(
                "Internal errors/reverts" in r for r in reason
            ):  # Avoid double penalty
                err_count = len(struct_log_data["execution_errors"])
                score -= 20  # Still a significant penalty
                reason.append(
                    f"Internal execution errors found in detailed trace ({err_count})"
                )

        # Penalize high step counts (scaled)
        num_steps = struct_log_data.get("total_steps", 0)
        if num_steps > 75_000:
            score -= min(18, (num_steps // 8000))  # Scaled penalty
            reason.append(f"Extremely high step count ({num_steps:,})")
        elif num_steps > 25_000:
            score -= min(10, (num_steps // 3000))
            reason.append(f"Very high step count ({num_steps:,})")

    # --- 4. Penalty if trace analysis failed ---
    trace_parse_failed = (
        call_trace_data is not None and call_trace_data.get("error")
    ) or (struct_log_data is not None and struct_log_data.get("error"))
    trace_exec_failed = (
        call_trace_data is not None and call_trace_data.get("trace_error")
    ) or (
        struct_log_data is not None and struct_log_data.get("execution_errors")
    )  # Check structlog exec errors too
    analysis_attempted = call_trace_data is not None or struct_log_data is not None

    # Apply penalty only if analysis was attempted but failed, and score is still high
    if analysis_attempted and (trace_parse_failed or trace_exec_failed):
        # Apply penalty if score is still high and no major errors already penalized
        if score > 85 and not any("Internal errors" in r for r in reason):
            score -= 10
            # Use a generic reason if trace failed
            if not any(r.startswith("Trace analysis failed") for r in reason):
                reason.append(
                    "Trace analysis failed or incomplete, limiting detailed scoring."
                )

    # --- Final Score Clamping and Failed Tx Handling ---
    score = max(0, min(100, score))  # Ensure score is between 0 and 100

    # Ensure failed complex transactions have a capped score and clear reason
    if status == 0 and actual_gas_used > 21000:
        score = min(score, 50)  # Cap score for failed complex tx
        if "failed" not in " ".join(reason).lower():  # Add reason if missing
            reason.append("Transaction failed")

    # Return score and reasons, or default message
    return score, ", ".join(reason) if reason else "Standard efficiency"


def suggest_optimizations(receipt_details, call_trace_data=None, struct_log_data=None):
    """Suggests optimizations based on reliable data from available traces."""
    suggestions = []
    if not receipt_details:
        return ["Receipt data unavailable."]

    actual_gas_used = _safe_hex_to_int(receipt_details.get("gasUsed", "0x0"))
    if actual_gas_used is None:
        actual_gas_used = 0
    status = _safe_hex_to_int(receipt_details.get("status"))

    # Get score and reasons to drive suggestions
    score, reason_str = calculate_gas_score(
        receipt_details, call_trace_data, struct_log_data
    )
    # Split reasons only if it's not the default message
    reason_list = reason_str.split(", ") if reason_str != "Standard efficiency" else []

    # --- Suggestions based on Score Reasons ---
    if any("gas usage" in r for r in reason_list):
        suggestions.append(
            f"Overall gas usage ({actual_gas_used:,}) is high. Review the primary contract interaction and core logic."
        )
    if any("call stack" in r for r in reason_list):
        depth = "N/A"
        # Try to get depth from callTracer if available
        if call_trace_data and call_trace_data.get("call_breakdown"):
            try:
                depth = str(max(c["depth"] for c in call_trace_data["call_breakdown"]))
            except ValueError:
                pass  # Handle empty breakdown case
        suggestions.append(
            f"Transaction involves deeply nested calls (max depth: {depth}). Consider optimizing call structure (batching, flattening)."
        )
    if any("internal calls" in r for r in reason_list):
        count = "N/A"
        # Try to get count from callTracer if available
        if call_trace_data and call_trace_data.get("call_breakdown"):
            # Count calls excluding the top level (depth 0)
            count = str(
                len([c for c in call_trace_data["call_breakdown"] if c["depth"] > 0])
            )
        suggestions.append(
            f"Numerous internal calls ({count}) contribute significantly to cost. Analyze if calls can be combined or logic moved."
        )
    if any("Expensive internal call" in r for r in reason_list):
        exp_call_reason = next(
            (r for r in reason_list if r.startswith("Expensive internal call")), None
        )
        detail = ""
        if exp_call_reason and " consumed " in exp_call_reason:
            # Try to extract the percentage part for context
            percent_match = re.search(
                r"\((\d+\.?\d*)%\)", exp_call_reason
            )  # Allow int or float %
            percent_str = (
                f" ({percent_match.group(1)}% of total)" if percent_match else ""
            )
            detail = f"{percent_str}"
        suggestions.append(
            f"An internal call consumes a large portion of the total gas{detail}. Focus optimization efforts on this specific interaction (details in Call Summary)."
        )
    if any("storage writes" in r for r in reason_list):
        count = "N/A"
        if struct_log_data and struct_log_data.get("opcode_frequency"):
            count = str(struct_log_data.get("opcode_frequency", {}).get("SSTORE", 0))
        suggestions.append(
            f"High number of storage writes detected ({count} SSTOREs). Minimize state changes, pack variables efficiently, use events for non-critical data, or consider transient storage (EIP-1153)."
        )
    if any("storage reads" in r for r in reason_list):
        count = "N/A"
        if struct_log_data and struct_log_data.get("opcode_frequency"):
            count = str(struct_log_data.get("opcode_frequency", {}).get("SLOAD", 0))
        suggestions.append(
            f"High number of storage reads detected ({count} SLOADs). Consider caching frequently accessed storage values in memory within function scope."
        )
    if any("step count" in r for r in reason_list):
        steps = "N/A"
        if struct_log_data and struct_log_data.get("total_steps") is not None:
            steps = f"{struct_log_data.get('total_steps'):,}"
        suggestions.append(
            f"Execution involves a large number of steps ({steps}). Review loops, complex calculations, or inefficient algorithms."
        )
    if any("Internal errors" in r for r in reason_list):
        suggestions.append(
            "Internal errors or reverts detected during execution trace. Investigate potential issues causing failures or wasted gas in the contract logic (see trace details)."
        )
    if any("Transaction failed" in r for r in reason_list):
        suggestions.append(
            "Transaction failed execution. Review the transaction details and trace errors (if available) to diagnose the failure."
        )

    # --- Suggestions based directly on Trace Data (if not covered by reasons) ---
    if struct_log_data and not struct_log_data.get("error"):
        top_steps = struct_log_data.get("top_expensive_steps", [])
        if top_steps and not any(
            "step count" in r for r in reason_list # Avoid redundancy if high steps already flagged
            or "storage reads" in r for r in reason_list # Avoid redundancy if SLOAD already flagged # type: ignore
            or "storage writes" in r for r in reason_list # Avoid redundancy if SSTORE already flagged
        ):
            step = top_steps[0] # Look at the most expensive non-call step
            # Only suggest if it's not already covered and cost is significant
            if step["gasCost"] > 5000: # Heuristic threshold
                 suggestions.append(
                    f"Expensive step found: {step['opcode']} (Reported Step Cost: {step['gasCost']:,}) at Step {step['step']}. Investigate this operation (check Detailed Steps)."
                 )

    # --- Fallback Suggestion ---
    if not suggestions and score < 80 and actual_gas_used > 30000:
        suggestions.append(
            "Gas usage is moderate to high. Consider general Solidity optimizations (data types, loop efficiency, external call patterns, algorithm review)."
        )
    elif not suggestions and actual_gas_used > 21000 and status == 1:
        suggestions.append(
            "No major specific optimization points detected based on available trace analysis."
        )
    elif not suggestions and status == 1:  # Successful simple transfer or low gas op
        suggestions.append("Transaction appears efficient or is a simple transfer.")
    elif not suggestions and status == 0:  # Failed and no other specific suggestion
        suggestions.append(
            "Transaction failed. Check details or trace errors for cause."
        )

    # --- Add Note about Trace Issues ---
    trace_analysis_error = (
        (call_trace_data and call_trace_data.get("error"))  # Parse error
        or (struct_log_data and struct_log_data.get("error"))  # Parse error
        or (call_trace_data and call_trace_data.get("trace_error"))  # Exec error
        or (struct_log_data and struct_log_data.get("execution_errors"))  # Exec error
    )

    # Add note if error occurred and not already present in suggestions
    if trace_analysis_error and not any(s.startswith("Note:") for s in suggestions):
        suggestions.append(
            "Note: Trace analysis encountered issues or was incomplete; suggestions may be limited."
        )

    return suggestions


# --- BigQuery Functions ---
def get_bq_client():
    """Helper to get BigQuery client using configured service account."""
    if not SERVICE_ACCOUNT_VALID:
        logging.error(
            "BigQuery client cannot be initialized: Service Account JSON missing or invalid."
        )
        return None
    try:
        if SERVICE_ACCOUNT_JSON_PATH:
            # Specify project explicitly if needed, though usually inferred
            return bigquery.Client.from_service_account_json(
                SERVICE_ACCOUNT_JSON_PATH, project=PROJECT_ID
            )
        elif SERVICE_ACCOUNT_JSON_CONTENT:
            credentials_info = json.loads(SERVICE_ACCOUNT_JSON_CONTENT)
            # Specify project explicitly if needed
            return bigquery.Client.from_service_account_info(
                credentials_info, project=PROJECT_ID
            )
        else:
            # Should not happen due to SERVICE_ACCOUNT_VALID check, but defensive
            logging.error("Service account configuration error.")
            return None
    except Exception as e:
        logging.exception(f"Failed to create BigQuery client: {e}")
        return None


def create_bigquery_table(table_id_str):
    """Creates the BigQuery table if it doesn't exist."""
    client = get_bq_client()
    if not client:
        return False
    try:
        # Define schema with BQ types explicitly
        schema = [
            bigquery.SchemaField("hash", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("blockNumber", "INTEGER", mode="NULLABLE"),
            bigquery.SchemaField("blockHash", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("transactionIndex", "INTEGER", mode="NULLABLE"),
            bigquery.SchemaField("from_address", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("to_address", "STRING", mode="NULLABLE"),
            bigquery.SchemaField(
                "value", "NUMERIC", mode="NULLABLE"
            ),  # Use NUMERIC for Wei values
            bigquery.SchemaField("gas_limit", "INTEGER", mode="NULLABLE"),
            bigquery.SchemaField(
                "gasPrice", "NUMERIC", mode="NULLABLE"
            ),  # Use NUMERIC for Wei values
            bigquery.SchemaField("input_data", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("nonce", "INTEGER", mode="NULLABLE"),
            bigquery.SchemaField("type", "INTEGER", mode="NULLABLE"),
            bigquery.SchemaField("chainId", "INTEGER", mode="NULLABLE"),
            bigquery.SchemaField("v", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("r", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("s", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("gasUsed", "INTEGER", mode="NULLABLE"),
            bigquery.SchemaField("cumulativeGasUsed", "INTEGER", mode="NULLABLE"),
            bigquery.SchemaField(
                "effectiveGasPrice", "NUMERIC", mode="NULLABLE"
            ),  # Use NUMERIC for Wei values
            bigquery.SchemaField("status", "INTEGER", mode="NULLABLE"),
            bigquery.SchemaField("contractAddress", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("load_timestamp", "TIMESTAMP", mode="REQUIRED"),
        ]
        table_ref = bigquery.TableReference.from_string(table_id_str)
        table = bigquery.Table(table_ref, schema=schema)
        try:
            client.get_table(table_ref)  # Check if table exists
            logging.debug(f"BigQuery table {table_id_str} already exists.")
        except exceptions.NotFound:
            logging.info(f"Table {table_id_str} not found. Creating...")
            client.create_table(table)
            logging.info(
                f"Created table {table.project}.{table.dataset_id}.{table.table_id}"
            )
        return True
    except ValueError as e:
        logging.error(f"Invalid BigQuery Table ID format '{table_id_str}': {e}")
        return False
    except exceptions.GoogleCloudError as e:
        logging.exception(
            f"BigQuery API error during table setup for {table_id_str}: {e}"
        )
        return False
    except Exception as e:
        logging.exception(
            f"Unexpected error during BigQuery table setup for {table_id_str}: {e}"
        )
        return False


def insert_transaction_to_bigquery(table_id_str, transaction_data):
    """Loads combined transaction details and receipt into BigQuery."""
    client = get_bq_client()
    if not client:
        logging.error("Cannot insert to BQ: Client not available.")
        return

    tx_hash_for_logging = "N/A"
    try:
        try:
            # Check table exists *before* preparing data
            table_ref = client.get_table(table_id_str).reference
        except exceptions.NotFound:
            logging.error(f"Cannot insert: BigQuery table {table_id_str} not found.")
            # Attempt to create it, but don't proceed if creation fails
            if not create_bigquery_table(table_id_str):
                logging.error(
                    f"Failed to create BQ table {table_id_str}, insertion aborted."
                )
                return
            # If creation succeeded, get the reference again
            table_ref = client.get_table(table_id_str).reference
        except exceptions.GoogleCloudError as e:
            logging.error(f"Cannot get BQ table reference for {table_id_str}: {e}")
            return

        load_time = datetime.datetime.now(datetime.timezone.utc)
        details = transaction_data.get("details") or {}
        receipt = transaction_data.get("receipt") or {}

        # Prioritize hash from details, fallback to receipt
        tx_hash_for_logging = details.get("hash") or receipt.get("transactionHash")
        if not tx_hash_for_logging or tx_hash_for_logging == "N/A":
            logging.error(
                "Tx hash missing in both details and receipt, cannot prepare BQ load job."
            )
            return

        # Prepare data row, carefully converting types
        bq_row_data = {
            "hash": tx_hash_for_logging,
            "blockNumber": _safe_hex_to_int(
                details.get("blockNumber") or receipt.get("blockNumber")
            ),
            "blockHash": details.get("blockHash") or receipt.get("blockHash"),
            "transactionIndex": _safe_hex_to_int(
                details.get("transactionIndex") or receipt.get("transactionIndex")
            ),
            "from_address": details.get("from"),
            "to_address": details.get("to"),
            "value": _safe_hex_to_numeric(
                details.get("value")
            ),  # Keep as Decimal for BQ NUMERIC
            "gas_limit": _safe_hex_to_int(details.get("gas")),
            "gasPrice": _safe_hex_to_numeric(
                details.get("gasPrice")
            ),  # Keep as Decimal
            "input_data": details.get("input"),
            "nonce": _safe_hex_to_int(details.get("nonce")),
            "type": _safe_hex_to_int(details.get("type")),
            "chainId": _safe_hex_to_int(details.get("chainId")),
            "v": details.get("v"),
            "r": details.get("r"),
            "s": details.get("s"),
            "gasUsed": _safe_hex_to_int(receipt.get("gasUsed")),
            "cumulativeGasUsed": _safe_hex_to_int(receipt.get("cumulativeGasUsed")),
            "effectiveGasPrice": _safe_hex_to_numeric(
                receipt.get("effectiveGasPrice")
            ),  # Keep as Decimal
            "status": _safe_hex_to_int(receipt.get("status")),
            "contractAddress": receipt.get("contractAddress"),
            "load_timestamp": load_time.isoformat(),  # Use standard ISO format for TIMESTAMP
        }

        # Filter out None values before creating JSON string
        row_filtered = {k: v for k, v in bq_row_data.items() if v is not None}

        # Convert Decimals to float/int for JSON compatibility IF NEEDED by JSON library
        # Standard json library handles Decimal if context is set, but float is safer.
        # BigQuery client library might handle Decimal directly in newer versions.
        # Let's convert for broad compatibility.
        row_ready_for_json = {}
        for k, v in row_filtered.items():
            if isinstance(v, decimal.Decimal):
                # Convert to float, or int if it's a whole number
                row_ready_for_json[k] = float(v) if v % 1 != 0 else int(v)
            else:
                row_ready_for_json[k] = v

        json_string = json.dumps(row_ready_for_json) + "\n"
        data_stream = io.BytesIO(json_string.encode("utf-8"))

        job_config = LoadJobConfig(
            source_format=SourceFormat.NEWLINE_DELIMITED_JSON,
            write_disposition=WriteDisposition.WRITE_APPEND,  # Append new records
            schema=client.get_table(table_ref).schema,  # Use schema from existing table
            ignore_unknown_values=True,  # Ignore fields in JSON not in schema
        )

        logging.info(f"Starting BigQuery Load Job for tx {tx_hash_for_logging}...")
        load_job = client.load_table_from_file(
            data_stream, table_ref, job_config=job_config
        )
        load_job.result(timeout=90)  # Wait for job completion

        if load_job.errors:
            # Log detailed errors if available
            error_details = str(getattr(load_job, "errors", []))[:1000]
            logging.error(
                f"BigQuery Load Job failed for tx {tx_hash_for_logging}. Errors: {error_details}"
            )
        elif load_job.output_rows is not None and load_job.output_rows > 0:
            logging.info(
                f"BigQuery Load Job completed for tx {tx_hash_for_logging}. Rows loaded: {load_job.output_rows}."
            )
        else:
            # Job might complete but load 0 rows (e.g., if data already exists and disposition is different)
            logging.warning(
                f"BigQuery Load Job completed for tx {tx_hash_for_logging} but loaded 0 rows. Job state: {load_job.state}"
            )

    except exceptions.Forbidden as e:
        logging.error(f"BQ Permission Error inserting {tx_hash_for_logging}: {e}.")
    except exceptions.GoogleCloudError as e:
        logging.exception(
            f"BigQuery API error during load job for {tx_hash_for_logging}: {e}"
        )
    except Exception as e:
        logging.exception(
            f"Unexpected error during BQ Load Job for {tx_hash_for_logging}: {e}"
        )


def query_inserted_transaction(table_id_str, transaction_hash):
    """Queries BigQuery for the latest entry of a specific transaction hash."""
    client = get_bq_client()
    if not client:
        return None
    try:
        # Validate table ID format before using in query
        if not re.match(
            r"^[a-zA-Z0-9-_]+[.][a-zA-Z0-9-_]+[.][a-zA-Z0-9-_]+$", table_id_str
        ):
            logging.error(f"Invalid BQ table ID format for query: '{table_id_str}'")
            return None

        # Ensure identifiers are quoted
        query = f"SELECT * FROM `{table_id_str}` WHERE `hash` = @tx_hash ORDER BY `load_timestamp` DESC LIMIT 1"

        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("tx_hash", "STRING", transaction_hash)
            ],
            use_legacy_sql=False,  # Explicitly use Standard SQL
        )

        logging.debug(
            f"Executing BQ Query: {query} with param: {transaction_hash}"
        )
        query_job = client.query(query, job_config=job_config)
        # Wait for query completion, timeout if necessary
        results = list(query_job.result(timeout=30))

        if results:
            row = results[0]  # Get the first (and only) row
            row_dict = {}
            # Convert BQ row to dictionary, handling types for JSON compatibility
            for k, v in row.items():
                if isinstance(v, decimal.Decimal):
                    # Convert BQ NUMERIC (Decimal) to float for JSON
                    row_dict[k] = float(v)
                elif isinstance(v, datetime.datetime):
                    # Ensure timezone is UTC and format as ISO 8601 with Zulu indicator
                    ts = (
                        v.replace(tzinfo=datetime.timezone.utc)
                        if v.tzinfo is None
                        else v.astimezone(datetime.timezone.utc)  # Convert if needed
                    )
                    row_dict[k] = ts.strftime(
                        "%Y-%m-%dT%H:%M:%S.%fZ"
                    )  # Standard UTC format
                elif isinstance(v, bytes):
                    # Convert bytes to hex string, prefix with 0x
                    row_dict[k] = "0x" + v.hex()
                elif isinstance(v, float) and v.is_integer():
                    # Convert float that represents integer (e.g., 1.0) to int
                    row_dict[k] = int(v)
                else:
                    # Keep other types (string, int, bool, None) as is
                    row_dict[k] = v
            logging.debug(f"Found tx {transaction_hash} in BQ.")
            return row_dict
        else:
            logging.debug(f"Tx {transaction_hash} not found in BQ (query).")
            return None
    except ValueError as e:
        # Error in configuration or query parameters
        logging.error(f"Configuration or parameter error during BQ query: {e}")
        return None
    except exceptions.GoogleCloudError as e:
        # Catch BQ API errors specifically (includes BadRequest, NotFound, etc.)
        logging.exception(f"BigQuery API error querying for tx {transaction_hash}: {e}")
        return None
    except Exception as e:
        # Catch any other unexpected errors
        logging.exception(
            f"Unexpected error querying BQ for tx {transaction_hash}: {e}"
        )
        return None


# --- Main API View ---
@csrf_exempt
def process_transaction(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    transaction_hash = None
    try:
        # --- Input Processing & Validation ---
        try:
            data = json.loads(request.body.decode("utf-8"))
            transaction_hash = data.get("transactionHash")
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logging.error(f"Invalid request body: {e}")
            return JsonResponse(
                {"message": "Invalid request format.", "error": "Invalid Input"},
                status=400,
            )

        if (
            not transaction_hash
            or not isinstance(transaction_hash, str)
            or not re.match(r"^0x[0-9a-fA-F]{64}$", transaction_hash)
        ):
            return JsonResponse(
                {
                    "message": "Valid transactionHash (0x...) is required.",
                    "error": "Invalid Input",
                },
                status=400,
            )

        # --- Environment & BQ Setup Check ---
        if (
            not GCP_BLOCKCHAIN_RPC_ENDPOINT
            or not PROJECT_ID
            or not DATASET_ID
            or not TABLE_ID
            or not SERVICE_ACCOUNT_VALID
        ):
            logging.critical("CRITICAL: Server configuration incomplete (RPC/BQ/SA).")
            return JsonResponse(
                {
                    "message": "Server configuration error.",
                    "error": "Configuration Error",
                },
                status=500,
            )
        table_id_str = f"{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}"
        # Ensure table exists or can be created before proceeding
        if not create_bigquery_table(table_id_str):
            logging.error("Failed to ensure BigQuery table exists.")
            return JsonResponse(
                {
                    "message": "Failed to initialize backend data store.",
                    "error": "Backend Setup Error",
                },
                status=500,
            )

        # --- Initial Data Fetching ---
        logging.info(f"Processing transaction: {transaction_hash}")
        transaction_details = get_transaction_details(transaction_hash)
        transaction_receipt = get_transaction_receipt(transaction_hash)

        # --- Handle Not Found / Pending ---
        if not transaction_details and not transaction_receipt:
            logging.warning(
                f"Tx {transaction_hash} not found via RPC. Checking BQ cache."
            )
            bq_data = query_inserted_transaction(table_id_str, transaction_hash)
            if bq_data:
                return JsonResponse(
                    {
                        "message": "Live transaction data unavailable, returning cached data from BigQuery.",
                        "bigquery_data": bq_data,
                        "live_details": None,
                        "live_receipt": None,
                        "trace_analysis": None,
                        "error": "Live RPC data unavailable",  # Frontend can show this is cached
                    },
                    status=200,
                )
            else:
                return JsonResponse(
                    {
                        "message": "Transaction not found via RPC or in cache.",
                        "error": "Not Found",
                    },
                    status=404,
                )

        if not transaction_receipt:
            logging.warning(
                f"Tx {transaction_hash} found but receipt missing (likely pending)."
            )
            # Insert details only into BQ if it exists (allows tracking pending txs)
            if transaction_details:
                combined_pending_data = {
                    "details": transaction_details,
                    "receipt": None,
                }
                insert_transaction_to_bigquery(table_id_str, combined_pending_data)
            # Query BQ again to potentially get the newly inserted pending record
            bq_data_pending = query_inserted_transaction(table_id_str, transaction_hash)
            return JsonResponse(
                {
                    "message": "Transaction found but pending (receipt unavailable). Analysis cannot be performed yet.",
                    "bigquery_data": bq_data_pending,  # Return BQ data if found
                    "live_details": transaction_details,
                    "live_receipt": None,
                    "trace_analysis": None,
                    "error": "Transaction pending",
                },
                status=202,  # Accepted, but not fully processed
            )

        # --- Insert/Update Full Data in BigQuery (if receipt available) ---
        combined_data_for_bq = {
            "details": transaction_details,
            "receipt": transaction_receipt,
        }
        insert_transaction_to_bigquery(table_id_str, combined_data_for_bq)

        # --- Trace Analysis (Only if Tx Succeeded) ---
        call_trace_analysis = None
        struct_log_analysis = None
        analysis_type_performed = "none"
        final_trace_error = None
        receipt_status = _safe_hex_to_int(transaction_receipt.get("status"))

        if receipt_status == 1:
            logging.info(
                f"Transaction {transaction_hash} succeeded. Fetching traces..."
            )
            # Fetch both traces concurrently (potential future optimization) or sequentially
            struct_log_raw, struct_log_fetch_err = get_struct_log_trace(
                transaction_hash
            )
            call_trace_raw, call_trace_fetch_err = get_call_trace(transaction_hash)

            # Parse independently and consolidate errors
            # callTracer processing
            if call_trace_raw:
                call_trace_analysis = parse_call_trace(call_trace_raw)
                # Prioritize parsing error, then execution error from callTracer
                if call_trace_analysis.get("error"):
                    final_trace_error = (
                        f"callTracer parse error: {call_trace_analysis['error']}"
                    )
                elif call_trace_analysis.get("trace_error"):
                    final_trace_error = (
                        f"callTracer exec error: {call_trace_analysis['trace_error']}"
                    )
            elif call_trace_fetch_err:
                # If fetch failed, record that as the primary error for callTracer
                final_trace_error = f"callTracer fetch error: {call_trace_fetch_err}"

            # structLog processing (append errors if callTracer already had one)
            if struct_log_raw:
                struct_log_analysis = parse_struct_log_trace(struct_log_raw)
                struct_log_parse_error = struct_log_analysis.get("error")
                if struct_log_parse_error:
                    struct_log_error_msg = (
                        f"structLog parse error: {struct_log_parse_error}"
                    )
                    # Append error, don't overwrite existing callTracer error
                    final_trace_error = (
                        f"{final_trace_error}; {struct_log_error_msg}"
                        if final_trace_error
                        else struct_log_error_msg
                    )
            elif struct_log_fetch_err:
                struct_log_error_msg = f"structLog fetch error: {struct_log_fetch_err}"
                # Append fetch error
                final_trace_error = (
                    f"{final_trace_error}; {struct_log_error_msg}"
                    if final_trace_error
                    else struct_log_error_msg
                )

            # Determine overall analysis success level based on *parsed* results having no errors
            # Check for successful parsing AND no execution errors within the trace itself
            call_ok = (
                call_trace_analysis
                and not call_trace_analysis.get("error")
                and not call_trace_analysis.get("trace_error")
            )
            struct_ok = (
                struct_log_analysis
                and not struct_log_analysis.get("error")
                and not struct_log_analysis.get(
                    "execution_errors"
                )  # Check internal exec errors too
            )

            if call_ok and struct_ok:
                analysis_type_performed = "detailed"
            elif call_ok:
                analysis_type_performed = "simple"
            elif struct_ok:
                analysis_type_performed = "detailed_only"
            else:
                analysis_type_performed = (
                    "none"  # Both failed or had errors preventing full analysis
                )

        else:  # Tx Failed (Status 0 or other non-1)
            logging.info(
                f"Skipping trace analysis for failed transaction {transaction_hash} (Status: {receipt_status})"
            )
            final_trace_error = f"Trace analysis skipped for failed transaction (status {receipt_status})."
            analysis_type_performed = "none"

        # --- Scoring & Suggestions ---
        # Pass combined data for scoring context if needed (like input data check)
        # We include 'details' here as calculate_gas_score might check transaction input
        scoring_receipt_details = {
            **(transaction_receipt or {}),  # Use receipt if available
            "details": transaction_details, # Pass details for potential checks like input data
        }
        gas_score, score_reason = calculate_gas_score(
            scoring_receipt_details, call_trace_analysis, struct_log_analysis
        )
        optimizations = suggest_optimizations(
            scoring_receipt_details, call_trace_analysis, struct_log_analysis
        )

        # --- Prepare Final Response ---
        trace_analysis_response = {
            "analysis_type_performed": analysis_type_performed,
            "call_trace_analysis": call_trace_analysis,
            "detailed_analysis": struct_log_analysis,
            "gas_efficiency_score": gas_score,
            "score_reason": score_reason,
            "optimizations": optimizations,
            "error": final_trace_error,  # Consolidated error message
        }

        # Query BQ one last time to get the final state after insertion/update
        bq_confirmation_data = query_inserted_transaction(
            table_id_str, transaction_hash
        )

        status_code = 200
        response_message = "Transaction processed successfully."
        # Refine message based on trace outcome
        if final_trace_error and not final_trace_error.startswith(
            "Trace analysis skipped"
        ):
            if analysis_type_performed in ["simple", "detailed_only"]:
                status_code = 206  # Partial Content - some trace data is useful
                response_message = f"Transaction processed, but trace analysis was partial: {final_trace_error}"
            else:  # analysis_type_performed == 'none' but tx succeeded
                response_message = f"Transaction processed, but trace analysis failed: {final_trace_error}"
                # Keep status 200 as base data is fine, error indicates trace failure
        elif final_trace_error:  # Failed tx case ("skipped...")
            response_message = f"Transaction processed. {final_trace_error}"
        elif (
            analysis_type_performed == "none" and receipt_status == 1
        ):  # Succeeded but somehow no trace data recovered (fetch/parse failed silently?)
            response_message = "Transaction processed, but trace data was unavailable."
            # Add error to trace_analysis if not already set by fetch/parse failures
            if not trace_analysis_response.get("error"):
                trace_analysis_response["error"] = (
                    "Trace data unavailable from endpoint or parsing failed."
                )

        response_data = {
            "message": response_message,
            "bigquery_data": bq_confirmation_data,  # Return the data confirmed from BQ
            "live_details": transaction_details,
            "live_receipt": transaction_receipt,
            "trace_analysis": trace_analysis_response,
        }
        return JsonResponse(response_data, status=status_code)

    # --- Global Exception Handling ---
    except Exception as e:
        # Log the full traceback for unexpected errors
        logging.exception(
            f"CRITICAL UNEXPECTED ERROR processing tx {transaction_hash}: {e}"
        )
        # Return a generic 500 error to the client
        return JsonResponse(
            {
                "message": "An internal server error occurred during processing.",
                "error": "Internal Server Error",
            },
            status=500,
        )
