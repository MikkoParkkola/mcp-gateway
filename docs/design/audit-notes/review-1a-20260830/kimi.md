synthetic-review: request failed (exit 1) -- NOT a review, no verdict
  synthetic-review: [synthetic] attempt 1 failed (ValueError("finish_reason='length', not 'stop' -- incomplete review")); retrying in 2s
  synthetic-review: [synthetic] attempt 2 failed (HTTP Error 429: Too Many Requests
  {"error":"You've exceeded your subscription rate limits. Upgrade, or try again later. You can view your usage at https://synthetic.new/billing"}); retrying in 4s
  synthetic-review: [ollama] attempt 1 failed (ValueError("finish_reason='length', not 'stop' -- incomplete review")); retrying in 2s
  synthetic-review: [ollama] attempt 2 failed (ValueError("finish_reason='length', not 'stop' -- incomplete review")); retrying in 4s
  synthetic-review: request failed after all providers:
    [synthetic/hf:moonshotai/Kimi-K3] HTTP Error 429: Too Many Requests
  {"error":"You've exceeded your subscription rate limits. Upgrade, or try again later. You can view your usage at https://synthetic.new/billing"}
    [ollama/kimi-k3] ValueError("finish_reason='length', not 'stop' -- incomplete review")
