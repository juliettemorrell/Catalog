"""Reference data for runtime end-of-life dates and retired/deprecated LLM model IDs.

Fetched: 2026-09-26

Sources
-------
RUNTIME_EOL:
  endoflife.date data. The API (https://endoflife.date/api/<product>.json and
  https://endoflife.date/api/v1/products/<product>) was blocked by the network
  egress proxy, so the same data was read from the endoflife.date source repo,
  which the API is generated from (release frontmatter "releaseCycle" and "eol"):
    https://raw.githubusercontent.com/endoflife-date/endoflife.date/master/products/python.md
    https://raw.githubusercontent.com/endoflife-date/endoflife.date/master/products/nodejs.md
    https://raw.githubusercontent.com/endoflife-date/endoflife.date/master/products/eclipse-temurin.md
    https://raw.githubusercontent.com/endoflife-date/endoflife.date/master/products/dotnet.md
    https://raw.githubusercontent.com/endoflife-date/endoflife.date/master/products/go.md
    https://raw.githubusercontent.com/endoflife-date/endoflife.date/master/products/ruby.md
    https://raw.githubusercontent.com/endoflife-date/endoflife.date/master/products/php.md
  None means no EOL date announced yet (eol: false upstream).
  "java" is Eclipse Temurin (product "eclipse-temurin"); Temurin has no 9, 10,
  12-15 cycles. "dotnet" covers .NET Core 2.0-3.1 and .NET 5+.
  Go releases have no fixed EOL until two newer minors ship, so the latest two
  cycles are None. Some cycles are future or preview releases per upstream.

MODEL_DEPRECATIONS:
  Anthropic: https://platform.claude.com/docs/en/about-claude/model-deprecations
    (docs.claude.com URL redirects here). Verified.
  OpenAI: https://platform.openai.com/docs/deprecations
    NOT FETCHED: blocked by the network egress proxy (developers.openai.com and
    openai.com were also blocked). No OpenAI entries included.
  Google Gemini: https://ai.google.dev/gemini-api/docs/deprecations
    NOT FETCHED: blocked by the network egress proxy (the Vertex AI
    model-versions page on docs.cloud.google.com was also blocked). No Gemini
    entries included.

  Value: (status, retirement_date, recommended_replacement)
    status "retired": shut down as of 2026-09-26
    status "deprecated": announced, not yet retired
  Dates apply to Anthropic-operated platforms (Claude API, Claude Platform on
  AWS, Microsoft Foundry); Amazon Bedrock and Google Cloud set their own dates.
"""

RUNTIME_EOL: dict[str, dict[str, str | None]] = {
    "python": {
        "2.7": "2020-01-01",
        "3.4": "2019-03-18",
        "3.5": "2020-09-30",
        "3.6": "2021-12-23",
        "3.7": "2023-06-27",
        "3.8": "2024-10-07",
        "3.9": "2025-10-31",
        "3.10": "2026-10-31",
        "3.11": "2027-10-31",
        "3.12": "2028-10-31",
        "3.13": "2029-10-31",
        "3.14": "2030-10-31",
    },
    "nodejs": {
        "8": "2019-12-31",
        "9": "2018-06-30",
        "10": "2021-04-30",
        "11": "2019-06-30",
        "12": "2022-04-30",
        "13": "2020-06-01",
        "14": "2023-04-30",
        "15": "2021-06-01",
        "16": "2023-09-11",
        "17": "2022-06-01",
        "18": "2025-04-30",
        "19": "2023-06-01",
        "20": "2026-04-30",
        "21": "2024-06-01",
        "22": "2027-04-30",
        "23": "2025-06-01",
        "24": "2028-04-30",
        "25": "2026-06-01",
        "26": "2029-04-30",
    },
    # java: Eclipse Temurin (endoflife.date product eclipse-temurin)
    "java": {
        "8": "2030-12-31",
        "11": "2027-10-31",
        "16": "2021-09-30",
        "17": "2027-10-31",
        "18": "2022-09-30",
        "19": "2023-03-31",
        "20": "2023-09-19",
        "21": "2029-12-31",
        "22": "2024-09-17",
        "23": "2025-03-18",
        "24": "2025-09-16",
        "25": "2031-09-30",
        "26": "2026-09-15",
    },
    "dotnet": {
        "2.0": "2018-10-01",
        "2.1": "2021-08-21",
        "2.2": "2019-12-23",
        "3.0": "2020-03-03",
        "3.1": "2022-12-13",
        "5": "2022-05-10",
        "6": "2024-11-12",
        "7": "2024-05-14",
        "8": "2026-11-10",
        "9": "2026-11-10",
        "10": "2028-11-14",
    },
    "go": {
        "1.15": "2021-08-16",
        "1.16": "2022-03-15",
        "1.17": "2022-08-02",
        "1.18": "2023-02-01",
        "1.19": "2023-09-06",
        "1.20": "2024-02-06",
        "1.21": "2024-08-13",
        "1.22": "2025-02-11",
        "1.23": "2025-08-12",
        "1.24": "2026-02-10",
        "1.25": "2026-08-19",
        "1.26": None,
        "1.27": None,
    },
    "ruby": {
        "2.3": "2019-03-31",
        "2.4": "2020-03-31",
        "2.5": "2021-03-31",
        "2.6": "2022-03-31",
        "2.7": "2023-03-31",
        "3.0": "2024-04-23",
        "3.1": "2025-03-26",
        "3.2": "2026-03-31",
        "3.3": "2027-03-31",
        "3.4": "2028-03-31",
        "4.0": "2029-03-31",
    },
    "php": {
        "5.6": "2018-12-31",
        "7.0": "2019-01-10",
        "7.1": "2019-12-01",
        "7.2": "2020-11-30",
        "7.3": "2021-12-06",
        "7.4": "2022-11-28",
        "8.0": "2023-11-26",
        "8.1": "2025-12-31",
        "8.2": "2026-12-31",
        "8.3": "2027-12-31",
        "8.4": "2028-12-31",
        "8.5": "2029-12-31",
    },
}

MODEL_DEPRECATIONS: dict[str, tuple[str, str | None, str | None]] = {
    # Anthropic (verified 2026-09-26)
    "claude-mythos-preview": ("deprecated", None, None),  # deprecated 2026-06-09, retirement TBA
    "claude-opus-4-1-20250805": ("retired", "2026-08-05", "claude-opus-4-8"),
    "claude-sonnet-4-20250514": ("retired", "2026-06-15", "claude-sonnet-4-6"),
    "claude-opus-4-20250514": ("retired", "2026-06-15", "claude-opus-4-8"),
    "claude-3-haiku-20240307": ("retired", "2026-04-20", "claude-haiku-4-5-20251001"),
    "claude-3-5-haiku-20241022": ("retired", "2026-02-19", "claude-haiku-4-5-20251001"),
    "claude-3-7-sonnet-20250219": ("retired", "2026-02-19", "claude-sonnet-4-6"),
    "claude-3-5-sonnet-20240620": ("retired", "2025-10-28", "claude-sonnet-4-6"),
    "claude-3-5-sonnet-20241022": ("retired", "2025-10-28", "claude-sonnet-4-6"),
    "claude-3-opus-20240229": ("retired", "2026-01-05", "claude-opus-4-8"),
    "claude-2.0": ("retired", "2025-07-21", "claude-opus-4-8"),
    "claude-2.1": ("retired", "2025-07-21", "claude-opus-4-8"),
    "claude-3-sonnet-20240229": ("retired", "2025-07-21", "claude-sonnet-4-6"),
    "claude-1.0": ("retired", "2024-11-06", "claude-haiku-4-5-20251001"),
    "claude-1.1": ("retired", "2024-11-06", "claude-haiku-4-5-20251001"),
    "claude-1.2": ("retired", "2024-11-06", "claude-haiku-4-5-20251001"),
    "claude-1.3": ("retired", "2024-11-06", "claude-haiku-4-5-20251001"),
    "claude-instant-1.0": ("retired", "2024-11-06", "claude-haiku-4-5-20251001"),
    "claude-instant-1.1": ("retired", "2024-11-06", "claude-haiku-4-5-20251001"),
    "claude-instant-1.2": ("retired", "2024-11-06", "claude-haiku-4-5-20251001"),
    # OpenAI: long-retired models only (announced on platform.openai.com/docs/deprecations;
    # the page could not be re-fetched on 2026-09-26, so only well-established shutdowns
    # are listed). Extend as needed.
    "text-davinci-003": ("retired", "2024-01-04", "gpt-4o-mini"),
    "text-davinci-002": ("retired", "2024-01-04", "gpt-4o-mini"),
    "text-davinci-001": ("retired", "2024-01-04", "gpt-4o-mini"),
    "code-davinci-002": ("retired", "2024-01-04", "gpt-4o-mini"),
    "text-curie-001": ("retired", "2024-01-04", "gpt-4o-mini"),
    "text-babbage-001": ("retired", "2024-01-04", "gpt-4o-mini"),
    "text-ada-001": ("retired", "2024-01-04", "gpt-4o-mini"),
    "gpt-3.5-turbo-0301": ("retired", "2024-09-13", "gpt-4o-mini"),
    "gpt-3.5-turbo-0613": ("retired", "2024-09-13", "gpt-4o-mini"),
    "gpt-3.5-turbo-16k-0613": ("retired", "2024-09-13", "gpt-4o-mini"),
    # Google Gemini: source page blocked by egress proxy; nothing verified, nothing included.
}
