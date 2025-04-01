import React, { useState } from "react";
import { Tooltip } from "react-tooltip";

// --- Interfaces ---

interface TransactionDetails {
  hash?: string | null;
  blockNumber?: number | string | null;
  blockHash?: string | null;
  transactionIndex?: number | string | null;
  from_address?: string | null;
  from?: string | null;
  to_address?: string | null;
  to?: string | null;
  value?: number | string | null;
  gas_limit?: number | string | null; // Source: BQ(number) or RPC(hex string via 'gas')
  gas?: string | null; // Alias for RPC 'gas' field (hex string limit)
  gasPrice?: number | string | null; // Legacy
  input_data?: string | null;
  input?: string | null;
  nonce?: number | string | null;
  type?: number | string | null;
  chainId?: number | string | null;
  v?: string | null;
  r?: string | null;
  s?: string | null;
  gasUsed?: number | string | null; // Canonical gas used from receipt
  cumulativeGasUsed?: number | string | null;
  effectiveGasPrice?: number | string | null;
  status?: number | string | null;
  contractAddress?: string | null;
  load_timestamp?: string | null;
  [key: string]: any;
}

interface TransactionReceipt {
  blockHash: string;
  blockNumber: string;
  contractAddress: string | null;
  cumulativeGasUsed: string;
  effectiveGasPrice: string;
  from: string;
  gasUsed: string; // Canonical gas used (hex string)
  logs: any[];
  logsBloom: string;
  status: string; // Usually "0x1" or "0x0"
  to: string | null;
  transactionHash: string;
  transactionIndex: string;
  type: string;
}

// structLog results (reliable parts only)
interface DetailedTraceAnalysis {
  gas_reported_in_trace?: number | null; // Gas from trace result object
  opcode_frequency?: { [key: string]: number }; // Counts are reliable
  top_expensive_steps?: Array<{
    // Filtered non-CALL steps
    step: number;
    pc: number;
    opcode: string;
    gasCost: number; // Cost at step execution
    depth: number;
  }>;
  execution_errors?: Array<{
    // Errors are reliable
    step: number;
    pc?: number;
    depth?: number;
    error: string;
  }>;
  total_steps?: number; // Reliable
  error?: string | null; // Parsing error for this trace type
}

// callTracer results (reliable for call structure/gas)
interface SimpleTraceAnalysis {
  // *** CHANGED: Use specific top-level gas ***
  top_level_call_gas_used?: number; // Gas from the top-level call (should match receipt)
  call_breakdown?: Array<{
    // Call hierarchy (reliable)
    depth: number;
    type: string;
    from: string;
    to: string;
    input: string;
    output: string;
    gasUsed: number; // NET gas used *within* this call frame (reliable)
    error: string | null; // Internal call error (reliable)
  }>;
  trace_error?: string | null; // Overall execution error reported by tracer
  error?: string | null; // Parsing error for this trace type
}

// Combined analysis object from backend
interface TraceAnalysis {
  analysis_type_performed?: "simple" | "detailed" | "detailed_only" | "none";
  call_trace_analysis?: SimpleTraceAnalysis | null; // Result from callTracer parsing
  detailed_analysis?: DetailedTraceAnalysis | null; // Result from structLog parsing (simplified)
  gas_efficiency_score?: number;
  score_reason?: string;
  optimizations?: string[];
  error?: string | null; // Consolidated error message from backend trace attempts
}

interface ApiResponse {
  message: string;
  bigquery_data?: TransactionDetails | null;
  live_details?: TransactionDetails | null;
  live_receipt?: TransactionReceipt | null;
  trace_analysis?: TraceAnalysis | null;
  error?: string; // Top-level backend processing error
}

// --- Helper Functions ---

const safeHexToInt = (
  value: string | number | null | undefined
): number | null => {
  if (value === null || typeof value === "undefined") return null;
  if (typeof value === "number") return Math.round(value);
  if (typeof value !== "string") return null;
  try {
    if (/^\d+$/.test(value)) return parseInt(value, 10);
    const hexString = value.startsWith("0x") ? value : `0x${value}`;
    const num = parseInt(hexString, 16);
    return isNaN(num) ? null : num;
  } catch {
    return null;
  }
};

const safeHexToBigInt = (
  value: string | number | null | undefined
): bigint | null => {
  if (value === null || typeof value === "undefined") return null;
  try {
    if (typeof value === "number") return BigInt(Math.round(value));
    if (typeof value === "string") {
      if (/^\d+$/.test(value)) return BigInt(value);
      const hex = value.startsWith("0x") ? value : `0x${value}`;
      return BigInt(hex);
    }
    return null;
  } catch {
    return null;
  }
};

const formatValue = (
  value: any,
  fieldName?: keyof TransactionDetails | string
): string => {
  if (value === null || typeof value === "undefined") return "N/A";

  if (fieldName === "status") {
    const numStatus = safeHexToInt(value);
    if (numStatus === 1) return "Success (1)";
    if (numStatus === 0) return "Failure (0)";
    return String(value);
  }

  const weiFields: (keyof TransactionDetails | string)[] = [
    "value",
    "gasPrice",
    "effectiveGasPrice",
  ];
  if (fieldName && weiFields.includes(fieldName)) {
    const numValue = safeHexToBigInt(value);
    if (numValue !== null) {
      const etherInWei = BigInt(1e18);
      const gweiInWei = BigInt(1e9);
      if (numValue === BigInt(0)) return "0 Ether";
      if (numValue >= etherInWei / BigInt(1_000_000)) {
        // Threshold ~0.000001 ETH
        const etherValue = Number(numValue) / Number(etherInWei);
        const decimals = etherValue < 0.01 ? 9 : 6;
        return `${etherValue.toFixed(decimals).replace(/\.?0+$/, "")} Ether`;
      }
      if (numValue >= gweiInWei) {
        // Threshold 1 Gwei
        const gweiValue = Number(numValue) / Number(gweiInWei);
        return `${gweiValue.toFixed(gweiValue % 1 !== 0 ? 3 : 0)} Gwei`;
      }
      return `${numValue.toLocaleString()} Wei`;
    }
  }

  const integerFields: (keyof TransactionDetails | string)[] = [
    "gasUsed", // Apply to receipt gasUsed as well
    "gas_limit",
    "cumulativeGasUsed",
    "nonce",
    "blockNumber",
    "transactionIndex",
    "type",
    "chainId",
    "gas", // Apply to tx gas limit alias
  ];
  if (fieldName && integerFields.includes(fieldName)) {
    const numValue = safeHexToInt(value);
    return typeof numValue === "number"
      ? numValue.toLocaleString()
      : String(value);
  }

  if (typeof value === "string") {
    if (value.startsWith("0x") && value.length === 42)
      return `${value.substring(0, 6)}...${value.substring(value.length - 4)}`;
    if (value.startsWith("0x") && value.length === 66)
      return `${value.substring(0, 10)}...${value.substring(value.length - 8)}`;
    if (value.startsWith("0x") && value.length > 66)
      return `${value.substring(0, 10)}... (${
        value.length - 2
      } hex chars) ...${value.substring(value.length - 8)}`;
    if (/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(value)) {
      try {
        return new Date(value).toLocaleString(undefined, {
          year: "numeric",
          month: "short",
          day: "numeric",
          hour: "numeric",
          minute: "2-digit",
          second: "2-digit",
          timeZoneName: "short",
        });
      } catch {
        /* ignore */
      }
    }
    if (value.length > 100) return value.substring(0, 97) + "...";
    return value;
  }

  if (typeof value === "number") {
    return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(4);
  }

  return String(value);
};

// --- Main Component ---
function App() {
  const [transactionHash, setTransactionHash] = useState("");
  const [displayData, setDisplayData] = useState<TransactionDetails | null>(
    null
  );
  // *** ADDED State: Store the canonical gas used from the receipt ***
  const [receiptGasUsed, setReceiptGasUsed] = useState<number | null>(null);
  const [traceAnalysis, setTraceAnalysis] = useState<TraceAnalysis | null>(
    null
  );
  const [apiMessage, setApiMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null); // For critical fetch/processing errors
  const [loading, setLoading] = useState(false);

  const isValidTransactionHash = (hash: string): boolean => {
    return /^0x[0-9a-fA-F]{64}$/.test(hash);
  };

  // --- handleSubmit ---
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setDisplayData(null);
    setTraceAnalysis(null);
    setReceiptGasUsed(null); // Reset receipt gas used
    setApiMessage("Fetching transaction data & traces...");

    if (!isValidTransactionHash(transactionHash)) {
      setError("Invalid transaction hash format.");
      setApiMessage(null);
      setLoading(false);
      return;
    }

    let finalDisplayData: TransactionDetails | null = null;
    let finalTraceAnalysis: TraceAnalysis | null = null;
    let finalApiMessage: string | null =
      "Fetching transaction data & traces...";
    let finalError: string | null = null;
    let finalReceiptGasUsed: number | null = null; // Variable to hold receipt gas

    try {
      const apiUrl =
        import.meta.env.VITE_API_URL ||
        "http://127.0.0.1:8000/api/transaction/";
      console.log("Requesting analysis from API:", apiUrl);

      const response = await fetch(apiUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ transactionHash: transactionHash }),
      });

      const contentType = response.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        const textResponse = await response.text();
        throw new Error(
          `Non-JSON response received (${
            response.status
          }): ${textResponse.substring(0, 500)}`
        );
      }

      const data: ApiResponse = await response.json();
      finalApiMessage = data.message || null; // Use backend message first

      // Handle critical backend errors
      if (data.error && response.status >= 400) {
        throw new Error(`Backend Error: ${data.error}`); // Prioritize specific backend error
      }
      // Handle other non-OK HTTP statuses (excluding expected 202, 206)
      if (!response.ok && response.status !== 202 && response.status !== 206) {
        throw new Error(
          `HTTP error ${response.status}: ${
            data.message || response.statusText
          }`
        );
      }

      // --- Process Base Data (Always attempt if response is OK/Partial/Pending) ---
      let combinedDetails: TransactionDetails = {
        ...(data.bigquery_data ?? {}),
        ...(data.live_details ?? {}),
      };
      if (data.live_receipt) {
        combinedDetails = {
          ...combinedDetails,
          status: data.live_receipt.status ?? combinedDetails.status,
          gasUsed: data.live_receipt.gasUsed ?? combinedDetails.gasUsed, // Prefer live receipt gas
          effectiveGasPrice:
            data.live_receipt.effectiveGasPrice ??
            combinedDetails.effectiveGasPrice,
          cumulativeGasUsed:
            data.live_receipt.cumulativeGasUsed ??
            combinedDetails.cumulativeGasUsed,
          contractAddress:
            data.live_receipt.contractAddress ??
            combinedDetails.contractAddress,
          from_address: combinedDetails.from_address ?? data.live_receipt.from,
          to_address: combinedDetails.to_address ?? data.live_receipt.to,
          gas_limit: combinedDetails.gas_limit ?? combinedDetails.gas, // Prefer gas_limit if available
          input_data: combinedDetails.input_data ?? combinedDetails.input,
        };
        // *** ADDED: Extract canonical receipt gas used ***
        finalReceiptGasUsed = safeHexToInt(data.live_receipt.gasUsed);
      }
      // If receipt wasn't live, try getting gas used from combined details (e.g., BQ data)
      if (finalReceiptGasUsed === null && combinedDetails.gasUsed) {
        finalReceiptGasUsed = safeHexToInt(combinedDetails.gasUsed);
      }

      // Ensure hash is populated
      if (!combinedDetails.hash && data.live_receipt?.transactionHash) {
        combinedDetails.hash = data.live_receipt.transactionHash;
      }
      // Populate aliases for consistent access in renderTableRows (and fix type for gas)
      combinedDetails.from = combinedDetails.from_address;
      combinedDetails.to = combinedDetails.to_address;
      combinedDetails.input = combinedDetails.input_data;
      const gasLimitValue = combinedDetails.gas_limit;
      if (typeof gasLimitValue === "number") {
        combinedDetails.gas = `0x${gasLimitValue.toString(16)}`;
      } else if (typeof gasLimitValue === "string") {
        combinedDetails.gas = gasLimitValue.startsWith("0x")
          ? gasLimitValue
          : `0x${gasLimitValue}`; // Ensure hex format
      } else {
        combinedDetails.gas = null;
      }

      finalDisplayData =
        Object.keys(combinedDetails).length > 0 ? combinedDetails : null;

      // --- Process Trace Analysis ---
      finalTraceAnalysis = data.trace_analysis || null;

      // Refine final message based on status and trace results
      if (response.status === 202) {
        // Pending
        finalApiMessage = data.message || "Transaction is pending.";
      } else if (response.status === 206) {
        // Partial trace
        finalApiMessage =
          data.message || "Transaction processed, trace analysis partial.";
      } else if (finalTraceAnalysis?.error) {
        // Trace had issues, use backend message
        finalApiMessage =
          data.message ||
          `Transaction processed, but trace analysis failed: ${finalTraceAnalysis.error}`;
      } else if (
        response.ok &&
        !finalTraceAnalysis &&
        data.live_receipt &&
        safeHexToInt(data.live_receipt.status) === 0
      ) {
        // Failed Tx, trace skipped - use backend message
        finalApiMessage =
          data.message || "Transaction failed, trace analysis skipped.";
      } else if (
        response.ok &&
        !finalTraceAnalysis &&
        data.live_receipt &&
        safeHexToInt(data.live_receipt.status) === 1
      ) {
        // Succeeded Tx, but somehow no trace? Use backend message or generic
        finalApiMessage =
          data.message ||
          "Transaction processed, but trace data was unavailable.";
      } else if (response.ok) {
        // General success
        finalApiMessage =
          finalApiMessage || "Transaction processed successfully.";
      }

      finalError = null; // Clear critical error if we processed successfully
    } catch (err: any) {
      console.error("API Fetch/Processing Error:", err);
      const message = err.message || "An unexpected error occurred.";
      finalError = message; // Set critical error state
      finalApiMessage =
        message.startsWith("HTTP error") ||
        message.startsWith("Non-JSON") ||
        message.startsWith("Backend Error")
          ? message // Use the direct error message
          : `Error: ${message}`; // Add prefix for other errors
      finalDisplayData = null; // Clear data on critical error
      finalTraceAnalysis = null;
      finalReceiptGasUsed = null; // Clear receipt gas on error
    } finally {
      // Set final states
      setError(finalError);
      setApiMessage(finalApiMessage);
      setDisplayData(finalDisplayData);
      setTraceAnalysis(finalTraceAnalysis);
      setReceiptGasUsed(finalReceiptGasUsed); // Set the extracted receipt gas
      setLoading(false);
    }
  };

  // --- renderTableRows ---
  // Add tooltip support to Gas Used row
  const renderTableRows = (data: TransactionDetails | null) => {
    if (!data) return null;
    const fieldOrder: Array<{
      key: keyof TransactionDetails | string;
      label: string;
      rpcFallbackKey?: keyof TransactionDetails;
      tooltip?: string; // Optional tooltip text
    }> = [
      { key: "hash", label: "Transaction Hash" },
      { key: "status", label: "Status (Receipt)" },
      { key: "blockNumber", label: "Block Number" },
      { key: "from_address", label: "From Address", rpcFallbackKey: "from" },
      { key: "to_address", label: "To Address", rpcFallbackKey: "to" },
      { key: "value", label: "Value Sent" },
      // *** ADDED Tooltip ***
      {
        key: "gasUsed",
        label: "Gas Used (Receipt)",
        tooltip:
          "The final, canonical gas amount consumed by the transaction, as recorded in the official receipt.",
      },
      { key: "effectiveGasPrice", label: "Effective Gas Price (Receipt)" },
      { key: "gas_limit", label: "Gas Limit (Tx)", rpcFallbackKey: "gas" }, // Use source key for lookup
      { key: "gasPrice", label: "Gas Price (Tx)" },
      { key: "input_data", label: "Input Data", rpcFallbackKey: "input" },
      { key: "nonce", label: "Nonce" },
      { key: "type", label: "Tx Type" },
      { key: "chainId", label: "Chain ID" },
      { key: "transactionIndex", label: "Tx Index" },
      { key: "contractAddress", label: "Contract Created (Receipt)" },
      { key: "blockHash", label: "Block Hash" },
      { key: "load_timestamp", label: "Loaded At (BigQuery)" },
    ];

    return fieldOrder
      .map(({ key, label, rpcFallbackKey, tooltip }) => {
        let effectiveKey = key as keyof TransactionDetails;
        let value = data[effectiveKey];

        // Use fallback if primary is missing
        if (
          (value === null || typeof value === "undefined") &&
          rpcFallbackKey
        ) {
          const fallbackValue = data[rpcFallbackKey];
          if (fallbackValue !== null && typeof fallbackValue !== "undefined") {
            value = fallbackValue;
            effectiveKey = rpcFallbackKey; // Important: use the key where value was found for formatting
          }
        }

        // Skip row if value is strictly null/undefined/empty string, with exceptions
        const isNullOrEmpty =
          value === null || typeof value === "undefined" || value === "";
        const isZero =
          (typeof value === "number" && value === 0) ||
          (typeof value === "bigint" && value === BigInt(0)) ||
          (typeof value === "string" && (value === "0" || value === "0x0"));

        if (
          isNullOrEmpty &&
          key !== "to_address" &&
          key !== "to" &&
          key !== "contractAddress"
        ) {
          if (key === "load_timestamp") return null; // Always hide if missing
          // Hide other non-essential null/empty rows, but *allow* zero values
          if (
            !isZero &&
            key !== "value" &&
            key !== "gasPrice" &&
            key !== "effectiveGasPrice"
          ) {
            return null;
          }
        }

        // Special 'To' address formatting for contract creation
        if (
          (key === "to_address" || key === "to") &&
          (value === null || value === undefined) &&
          data.contractAddress
        ) {
          value = `Contract Creation (${formatValue(
            data.contractAddress,
            "contractAddress"
          )})`;
        } else if (
          (key === "to_address" || key === "to") &&
          (value === null || value === undefined)
        ) {
          value = "N/A (Contract Creation or Null Address)";
        }
        // Hide 'Contract Created' row if null
        if (
          key === "contractAddress" &&
          (value === null || value === undefined)
        )
          return null;

        return (
          <tr key={label}>
            <td className="px-4 py-2 font-medium text-gray-600 border whitespace-nowrap">
              {label}
              {/* *** ADDED Tooltip Trigger *** */}
              {tooltip && (
                <span
                  data-tooltip-id="table-tooltip"
                  data-tooltip-content={tooltip}
                  data-tooltip-place="right"
                  className="ml-1 text-xs text-blue-500 cursor-help"
                >
                  (?)
                </span>
              )}
            </td>
            <td className="px-4 py-2 break-words border">
              {formatValue(value, effectiveKey)}
            </td>
          </tr>
        );
      })
      .filter(Boolean); // Filter out the nulls from skipped rows
  };

  // --- SimpleTraceView (callTracer results) ---
  const SimpleTraceView: React.FC<{
    analysis: SimpleTraceAnalysis;
    receiptGas: number | null;
  }> = ({ analysis, receiptGas }) => {
    const breakdown = analysis?.call_breakdown;
    const hasError = analysis?.error || analysis?.trace_error;
    const isEmpty = !breakdown || breakdown.length === 0; // Changed to 0 check
    const topLevelGas = analysis?.top_level_call_gas_used; // Use the correct field name

    return (
      <div>
        <h5 className="mb-1 text-sm font-semibold text-gray-700">
          Call Execution Summary (callTracer)
          {/* *** ADDED Tooltip *** */}
          <span
            data-tooltip-id="trace-tooltip"
            data-tooltip-content="Shows the call hierarchy and the NET gas consumed within each call frame. Useful for identifying costly internal operations."
            data-tooltip-place="right"
            className="ml-1 text-xs text-blue-500 cursor-help"
          >
            (?)
          </span>
        </h5>
        {analysis?.error && (
          <p className="mb-1 text-xs text-red-600">
            Parsing Error: {analysis.error}
          </p>
        )}
        {analysis?.trace_error && (
          <p className="mb-1 text-xs text-orange-600">
            Trace Execution Error: {analysis.trace_error}
          </p>
        )}
        {isEmpty && !hasError && (
          <p className="text-xs text-gray-500">
            No internal calls found or simple trace empty/unavailable.
          </p>
        )}

        {breakdown && breakdown.length > 0 && !analysis?.error && (
          <>
            {/* *** CHANGED: Show top-level gas and compare to receipt *** */}
            <div className="mb-2 text-xs text-gray-600 space-y-0.5">
              {" "}
              {/* Added space-y */}
              {typeof topLevelGas === "number" && (
                <p className="flex items-center">
                  {" "}
                  {/* Use flex for alignment */}
                  Top-Level Call Gas (Trace):&nbsp;{" "}
                  {/* Added non-breaking space */}
                  <span className="font-semibold">
                    {topLevelGas.toLocaleString()}
                  </span>
                  {receiptGas !== null && topLevelGas === receiptGas && (
                    <span className="ml-1 text-green-600">
                      (Matches Receipt)
                    </span>
                  )}
                  {receiptGas !== null && topLevelGas !== receiptGas && (
                    <span
                      className="ml-1 text-orange-600"
                      title={`Receipt Gas: ${receiptGas.toLocaleString()}`}
                    >
                      (Differs from Receipt: {receiptGas.toLocaleString()})
                    </span>
                  )}
                  {/* *** ADDED Tooltip *** */}
                  <span
                    data-tooltip-id="trace-tooltip"
                    data-tooltip-content="Gas consumed by the initial call frame, including all sub-calls. Should match the official Gas Used from the receipt."
                    data-tooltip-place="right"
                    className="ml-1 text-xs text-blue-500 cursor-help"
                  >
                    (?)
                  </span>
                </p>
              )}
              <p>
                Found {breakdown.length - 1 > 0 ? breakdown.length - 1 : 0}{" "}
                internal call(s).
              </p>
            </div>

            <div className="p-2 overflow-y-auto text-xs bg-gray-100 border rounded shadow-inner max-h-80">
              <ul className="space-y-1 font-mono">
                {breakdown.map((call, index) => (
                  <li
                    key={index}
                    style={{ paddingLeft: `${call.depth * 15}px` }}
                    className={`py-0.5 border-b border-gray-200 last:border-b-0 ${
                      call.error ? "text-red-600 bg-red-50" : ""
                    }`}
                  >
                    <span className="font-semibold">{call.type}</span>
                    {call.to && (
                      <span>
                        {" "}
                        to{" "}
                        <span className="text-blue-700">
                          {formatValue(call.to, "to_address")}
                        </span>
                      </span>
                    )}
                    <span className="inline-flex items-center ml-2">
                      {" "}
                      {/* Flex for alignment */}| Gas Consumed:&nbsp;{" "}
                      {/* This IS the net gas */}
                      <span className="font-semibold">
                        {call.gasUsed?.toLocaleString() ?? "N/A"}
                      </span>
                      {/* *** ADDED Tooltip *** */}
                      <span
                        data-tooltip-id="trace-tooltip"
                        data-tooltip-content="The NET gas consumed ONLY within this specific call's execution context (after refunds within the call)."
                        data-tooltip-place="right"
                        className="ml-0.5 text-[9px] text-blue-500 cursor-help" // Removed align-super, flex handles it
                      >
                        (?)
                      </span>
                    </span>
                    {call.input &&
                      call.input !== "0x" &&
                      call.input !== "0x..." && (
                        <span className="text-gray-500 text-[10px]">
                          {" "}
                          | In: {call.input}
                        </span>
                      )}
                    {call.output &&
                      call.output !== "0x" &&
                      call.output !== "0x..." && (
                        <span className="text-gray-500 text-[10px]">
                          {" "}
                          | Out: {call.output}
                        </span>
                      )}
                    {call.error && (
                      <span className="ml-2 font-bold text-red-700">
                        ! Error: {call.error}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          </>
        )}
      </div>
    );
  };

  // --- DetailedTraceView (structLog results - Simplified) ---
  const DetailedTraceView: React.FC<{ analysis: DetailedTraceAnalysis }> = ({
    analysis,
  }) => {
    const hasError = analysis?.error;
    const isEmpty =
      !analysis?.total_steps &&
      !analysis?.execution_errors?.length &&
      !analysis?.opcode_frequency; // Adjusted empty check
    const opcodeFrequency = analysis?.opcode_frequency ?? {};
    const expensiveSteps = analysis?.top_expensive_steps ?? [];
    const executionErrors = analysis?.execution_errors ?? [];

    return (
      <div className="pt-4 mt-4 border-t">
        <h5 className="mb-1 text-sm font-semibold text-gray-700">
          Detailed Execution Steps (structLog)
          {/* *** ADDED Tooltip *** */}
          <span
            data-tooltip-id="trace-tooltip"
            data-tooltip-content="Shows step-by-step EVM execution, opcode usage, and reported cost *at each step*. Useful for low-level debugging and finding costly individual opcodes (like SLOAD/SSTORE)."
            data-tooltip-place="right"
            className="ml-1 text-xs text-blue-500 cursor-help"
          >
            (?)
          </span>
        </h5>
        {hasError && (
          <p className="mb-1 text-xs text-red-600">
            Parsing Error: {analysis.error}
          </p>
        )}
        {isEmpty && !hasError && (
          <p className="text-xs text-gray-500">
            Detailed trace contains no execution steps or summary data.
          </p>
        )}

        {(!isEmpty || executionErrors.length > 0) && !hasError && (
          <>
            {/* *** UPDATED Label and ADDED Tooltip for Reported Gas *** */}
            <p className="flex items-center mb-2 text-xs text-gray-600">
              {" "}
              {/* Flex for alignment */}
              Total Steps: {analysis.total_steps?.toLocaleString() ?? "N/A"} |
              Gas Reported by Trace Provider:&nbsp;
              <span title="Gas value reported in the top-level trace response object">
                {analysis.gas_reported_in_trace?.toLocaleString() ?? "N/A"}
                {/* *** ADDED Tooltip *** */}
                <span
                  data-tooltip-id="trace-tooltip"
                  data-tooltip-content="The 'gas' value returned in the trace result object itself. May occasionally differ slightly from the official receipt gas due to tracer implementation details."
                  data-tooltip-place="right"
                  className="ml-1 text-xs text-blue-500 cursor-help"
                >
                  (?)
                </span>
              </span>
            </p>

            {/* Opcode Frequency Table */}
            {Object.keys(opcodeFrequency).length > 0 && (
              <div className="mb-4">
                <h5 className="mb-1 text-xs font-semibold text-gray-700">
                  Opcode Frequency (Top 10):
                </h5>
                <div className="p-2 overflow-y-auto text-xs bg-gray-100 border rounded shadow-inner max-h-40">
                  <table className="w-full table-fixed">
                    <colgroup>
                      <col style={{ width: "60%" }} />
                      <col style={{ width: "40%" }} />
                    </colgroup>
                    <thead>
                      <tr className="bg-gray-200">
                        <th className="px-1 py-0.5 font-medium text-left">
                          Opcode
                        </th>
                        <th className="px-1 py-0.5 font-medium text-right">
                          Count
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(opcodeFrequency)
                        .slice(0, 10)
                        .map(([op, count]) => (
                          <tr key={op} className="border-t border-gray-200">
                            <td className="px-1 py-0.5 truncate">{op}</td>
                            <td className="text-right px-1 py-0.5">
                              {count.toLocaleString()}
                            </td>
                          </tr>
                        ))}
                      {Object.keys(opcodeFrequency).length > 10 && (
                        <tr className="border-t border-gray-200">
                          <td
                            colSpan={2}
                            className="text-center text-gray-500 italic py-0.5"
                          >
                            ... and {Object.keys(opcodeFrequency).length - 10}{" "}
                            more
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Most Expensive Steps Table (Filtered Non-CALL) */}
            {expensiveSteps.length > 0 && (
              <div className="mb-4">
                <h5 className="mb-1 text-xs font-semibold text-gray-700">
                  Most Expensive Reported Steps (Non-CALL*, Top 10):
                </h5>
                {/* *** UPDATED Explanation *** */}
                <p className="mb-1 text-[10px] text-gray-500">
                  (*CALLs excluded as their step cost often includes gas stipend
                  and differs from net execution cost. See Call Summary.)
                </p>
                <div className="p-2 overflow-y-auto text-xs bg-gray-100 border rounded shadow-inner max-h-40">
                  <table className="w-full table-fixed">
                    <colgroup>
                      <col style={{ width: "15%" }} />
                      <col style={{ width: "35%" }} />
                      <col style={{ width: "25%" }} />
                      <col style={{ width: "10%" }} />
                      <col style={{ width: "15%" }} />
                    </colgroup>
                    <thead>
                      <tr className="bg-gray-200">
                        <th className="px-1 py-0.5 font-medium text-left">
                          Step
                        </th>
                        <th className="px-1 py-0.5 font-medium text-left">
                          Opcode
                        </th>
                        <th className="px-1 py-0.5 font-medium text-right">
                          Reported Cost
                          {/* *** ADDED Tooltip *** */}
                          <span
                            data-tooltip-id="trace-tooltip"
                            data-tooltip-content="Gas cost calculated by the EVM for executing this specific opcode step (includes factors like memory expansion, stipend for calls etc.). Not the net cost of a sub-call."
                            data-tooltip-place="top" // Adjust placement if needed
                            className="ml-0.5 text-[9px] text-blue-500 cursor-help"
                          >
                            (?)
                          </span>
                        </th>
                        <th className="px-1 py-0.5 font-medium text-right">
                          Depth
                        </th>
                        <th className="px-1 py-0.5 font-medium text-right">
                          PC
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {expensiveSteps.slice(0, 10).map((step) => (
                        <tr
                          key={step.step}
                          className="border-t border-gray-200"
                        >
                          <td className="px-1 py-0.5">{step.step}</td>
                          <td className="px-1 py-0.5 truncate">
                            {step.opcode}
                          </td>
                          <td className="text-right px-1 py-0.5">
                            {step.gasCost.toLocaleString()}
                          </td>
                          <td className="text-right px-1 py-0.5">
                            {step.depth}
                          </td>
                          <td className="text-right px-1 py-0.5">{step.pc}</td>
                        </tr>
                      ))}
                      {expensiveSteps.length > 10 && (
                        <tr className="border-t border-gray-200">
                          <td
                            colSpan={5}
                            className="text-center text-gray-500 italic py-0.5"
                          >
                            ... and {expensiveSteps.length - 10} more
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Execution Errors List */}
            {executionErrors.length > 0 && (
              <div className="mb-4">
                <h5 className="mb-1 text-xs font-semibold text-red-600">
                  Execution Errors ({executionErrors.length}):
                </h5>
                <div className="p-2 overflow-y-auto text-xs border rounded shadow-inner max-h-40 bg-red-50">
                  <ul className="space-y-1">
                    {executionErrors.slice(0, 10).map((err, i) => (
                      <li
                        key={i}
                        className="py-0.5 border-t border-red-200 first:border-t-0"
                      >
                        Step {err.step}: {err.error} (Depth:{" "}
                        {err.depth ?? "N/A"}, PC: {err.pc ?? "N/A"})
                      </li>
                    ))}
                    {executionErrors.length > 10 && (
                      <li className="py-0.5 border-t border-red-200 text-gray-500 italic">
                        ... and {executionErrors.length - 10} more
                      </li>
                    )}
                  </ul>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    );
  };

  // --- RETURN JSX (Main App Structure) ---
  return (
    // Add Tooltip component at the root level or near the top
    <div className="flex items-center justify-center min-h-screen px-4 py-8 bg-gradient-to-br from-blue-50 via-white to-purple-50">
      {/* Define tooltips - adjust styles as needed */}
      <Tooltip
        id="table-tooltip"
        style={{ maxWidth: "250px", fontSize: "0.75rem", zIndex: 10 }}
      />
      <Tooltip
        id="trace-tooltip"
        style={{ maxWidth: "300px", fontSize: "0.75rem", zIndex: 10 }}
      />

      <div className="w-full max-w-5xl px-8 pt-6 pb-8 mb-4 bg-white border border-gray-200 rounded-lg shadow-xl">
        <h2 className="block mb-6 text-3xl font-bold text-center text-gray-800">
          Ethereum Transaction Gas Auditor
        </h2>

        {/* Form */}
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label
              className="block mb-2 text-sm font-bold text-gray-700"
              htmlFor="transactionHash"
            >
              Transaction Hash:
            </label>
            <input
              className={`w-full px-3 py-2 leading-tight text-gray-700 border rounded shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                loading ? "bg-gray-100 cursor-not-allowed" : ""
              }`}
              id="transactionHash"
              type="text"
              placeholder="0x..."
              value={transactionHash}
              onChange={(e) => setTransactionHash(e.target.value)}
              required
              pattern="^0x[0-9a-fA-F]{64}$"
              title="Enter a 64-character hexadecimal transaction hash starting with 0x"
              disabled={loading}
            />
          </div>
          <div className="flex items-center justify-center my-6">
            <button
              className={`px-6 py-3 font-bold text-white rounded focus:outline-none focus:ring-4 focus:ring-opacity-50 transition duration-150 ease-in-out inline-flex items-center justify-center ${
                loading
                  ? "bg-gray-400 cursor-not-allowed focus:ring-gray-300"
                  : "bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 focus:ring-purple-300"
              }`}
              type="submit"
              disabled={loading}
            >
              {loading && (
                <svg
                  className="inline w-5 h-5 mr-3 -ml-1 text-white animate-spin"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                >
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  ></circle>
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  ></path>
                </svg>
              )}
              {loading ? "Analyzing..." : "Analyze Transaction"}
            </button>
          </div>
        </form>

        {/* Status Messages Area */}
        {apiMessage && (
          <div
            className={`mt-4 p-3 text-center rounded border text-sm ${
              error
                ? "bg-red-100 border-red-300 text-red-800"
                : apiMessage.toLowerCase().includes("error") ||
                  apiMessage.toLowerCase().includes("fail") ||
                  apiMessage.toLowerCase().includes("issue") ||
                  apiMessage.toLowerCase().includes("unavailable") ||
                  apiMessage.toLowerCase().includes("partial") ||
                  apiMessage.toLowerCase().includes("trace analysis issue")
                ? "bg-yellow-100 border-yellow-300 text-yellow-800"
                : apiMessage.toLowerCase().includes("pending")
                ? "bg-blue-100 border-blue-300 text-blue-800"
                : loading
                ? "bg-blue-100 border-blue-300 text-blue-800"
                : "bg-green-100 border-green-300 text-green-800"
            }`}
          >
            {apiMessage}
            {error && !apiMessage.includes(error) && (
              <span className="block mt-1 text-xs">Details: {error}</span>
            )}
          </div>
        )}
        {!loading && error && !apiMessage && (
          <div className="p-3 mt-4 text-sm text-center text-red-800 bg-red-100 border border-red-300 rounded">
            {" "}
            Error: {error}{" "}
          </div>
        )}

        {/* Results Sections Container */}
        {!loading && (displayData || traceAnalysis) && (
          <div className="grid grid-cols-1 gap-6 mt-6 md:grid-cols-2">
            {/* Transaction Summary Column */}
            {displayData ? (
              <div className="order-1 p-4 border rounded-md shadow-sm bg-gray-50">
                <h3 className="mb-3 text-xl font-semibold text-gray-700">
                  Transaction Summary
                </h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm border-collapse table-auto">
                    <tbody>{renderTableRows(displayData)}</tbody>
                  </table>{" "}
                </div>
              </div>
            ) : !error ? (
              <div className="order-1 p-4 border rounded-md shadow-sm bg-gray-50">
                <h3 className="mb-3 text-xl font-semibold text-gray-700">
                  Transaction Summary
                </h3>
                <p className="text-gray-500">Details unavailable.</p>
              </div>
            ) : null}

            {/* Gas Efficiency Analysis Column */}
            {traceAnalysis ? (
              <div className="order-2 p-4 border rounded-md shadow-sm bg-gray-50">
                <h3 className="mb-3 text-xl font-semibold text-gray-700">
                  Gas Efficiency Analysis
                </h3>

                {/* Score */}
                <div className="p-3 mb-4 bg-white border rounded shadow-sm">
                  <span className="font-semibold text-gray-800">
                    Efficiency Score:
                  </span>
                  <span
                    className={`ml-2 font-bold text-2xl ${
                      (traceAnalysis.gas_efficiency_score ?? 0) >= 80
                        ? "text-green-600"
                        : (traceAnalysis.gas_efficiency_score ?? 0) >= 50
                        ? "text-yellow-600"
                        : "text-red-600"
                    }`}
                  >
                    {" "}
                    {typeof traceAnalysis.gas_efficiency_score === "number"
                      ? `${traceAnalysis.gas_efficiency_score} / 100`
                      : "N/A"}{" "}
                  </span>
                  {traceAnalysis.score_reason && (
                    <p className="mt-1 text-sm text-gray-600">
                      Reason(s): {traceAnalysis.score_reason}
                    </p>
                  )}
                </div>

                {/* Optimizations */}
                <div className="mb-4">
                  <h4 className="mb-1 font-semibold text-gray-700">
                    Potential Optimizations:
                  </h4>
                  {traceAnalysis.optimizations &&
                  traceAnalysis.optimizations.length > 0 ? (
                    <ul className="pl-4 space-y-1 text-sm text-gray-700 list-disc list-inside">
                      {" "}
                      {traceAnalysis.optimizations.map((opt, index) => (
                        <li key={index}>{opt}</li>
                      ))}{" "}
                    </ul>
                  ) : (
                    <p className="text-sm text-gray-500">
                      No specific optimizations suggested or analysis
                      incomplete.
                    </p>
                  )}
                </div>

                {/* Combined Trace Details Section */}
                <div className="pt-4 mt-4 border-t">
                  <h4 className="mb-2 font-semibold text-gray-700">
                    Execution Trace Details
                  </h4>
                  {traceAnalysis.error && (
                    <p className="py-1 pl-2 mb-3 text-sm text-red-600 border-l-4 border-red-500 bg-red-50">
                      {" "}
                      Trace Analysis Issue: {traceAnalysis.error}{" "}
                    </p>
                  )}

                  {/* Call Tracer View - Pass receiptGasUsed */}
                  {traceAnalysis.call_trace_analysis ? (
                    <SimpleTraceView
                      analysis={traceAnalysis.call_trace_analysis}
                      receiptGas={receiptGasUsed} // Pass the canonical gas
                    />
                  ) : !traceAnalysis.error &&
                    traceAnalysis.analysis_type_performed !== "none" ? (
                    <div className="mt-4">
                      <h5 className="mb-1 text-sm font-semibold text-gray-700">
                        Call Execution Summary (callTracer)
                      </h5>
                      <p className="text-xs text-gray-500">
                        Simple trace (callTracer) data unavailable or parsing
                        failed.
                      </p>
                    </div>
                  ) : null}

                  {/* StructLog View */}
                  {traceAnalysis.detailed_analysis ? (
                    <DetailedTraceView
                      analysis={traceAnalysis.detailed_analysis}
                    />
                  ) : !traceAnalysis.error &&
                    traceAnalysis.analysis_type_performed !== "none" ? (
                    <div className="pt-4 mt-4 border-t">
                      <h5 className="mb-1 text-sm font-semibold text-gray-700">
                        Detailed Execution Steps (structLog)
                      </h5>
                      <p className="text-xs text-gray-500">
                        Detailed trace (structLog) data unavailable or parsing
                        failed.
                      </p>{" "}
                    </div>
                  ) : null}

                  {/* Message if analysis skipped */}
                  {traceAnalysis.error?.includes(
                    "skipped for failed transaction"
                  ) &&
                    !traceAnalysis.call_trace_analysis &&
                    !traceAnalysis.detailed_analysis && (
                      <p className="mt-4 text-sm text-yellow-600">
                        {traceAnalysis.error}
                      </p>
                    )}
                </div>
              </div>
            ) : !error ? (
              <div className="order-2 p-4 border rounded-md shadow-sm bg-gray-50">
                <h3 className="mb-3 text-xl font-semibold text-gray-700">
                  Gas Efficiency Analysis
                </h3>
                <p className="text-gray-500">
                  Run analysis or transaction is pending/failed.
                </p>
              </div>
            ) : null}
          </div>
        )}

        {/* Loading Overlay */}
        {loading && (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center transition-opacity duration-300 bg-gray-600 bg-opacity-75"
            aria-labelledby="modal-title"
            role="dialog"
            aria-modal="true"
          >
            <div className="flex items-center p-6 space-x-4 bg-white rounded-lg shadow-xl">
              <svg
                className="w-6 h-6 text-blue-600 animate-spin"
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
              >
                <circle
                  className="opacity-25"
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  strokeWidth="4"
                ></circle>
                <path
                  className="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                ></path>
              </svg>
              <span className="text-lg font-medium text-gray-700">
                Processing Transaction & Traces...
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
