// Only publish known codes. Fetch errors may include response data in their message.
export function failedProbe(error, iteration, latencyMs) {
  const codes = [error?.cause?.code, error?.code];
  let reason = 'CLIENT_ERROR';
  if (codes.includes('ECONNRESET')) reason = 'ECONNRESET';
  else if (error?.name === 'TimeoutError' || codes.some(code =>
    ['ETIMEDOUT', 'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT'].includes(code))) {
    reason = 'TIMEOUT';
  } else if (codes.includes('UND_ERR_SOCKET')) reason = 'SOCKET_ERROR';

  return {
    ok: false,
    status_code: 503,
    status_source: 'client',
    error: reason,
    timestamp: new Date().toISOString(),
    latency_ms: latencyMs,
    iteration,
  };
}
