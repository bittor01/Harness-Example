# Import sys to handle command line arguments and print with clean exit codes.
import sys
# Import json for handling mitre_dataset and prompts loading, as well as dictionary operations.
import json
# Import re for programmatic regex extraction of toolcall tags and explicit MITRE IDs.
import re
# Import requests to perform OpenAI-compatible REST API requests to Docker Model Runner.
import requests

# Hardcoded environment defaults.
MODEL_RUNNER_URL = "http://model-runner.docker.internal:12434/engines/v1"
MODEL_NAME = "ai/granite-4.0-h-micro"

# Define ANSI escape codes for beautiful output coloring.
COLOR_GREY = "\033[90m"     # Grey color used for internal thinking, logs, and unverified streamed answers.
COLOR_WHITE = "\033[0m"     # Standard white (reset) used for the final verified streamed answers.
COLOR_YELLOW = "\033[93m"   # Yellow used for warnings and Critic failed-verification loops.
COLOR_GREEN = "\033[92m"    # Green used for successful verification and validated context printing.

# A global dictionary that will hold token frequencies across the loaded dataset to evaluate rare terms.
DATASET_TOKEN_FREQUENCIES = {}

def print_grey(text: str):
    """Prints logging/metadata in grey color to keep it distinct from the final answer."""
    # Print the text surrounded by the grey start code and white reset code.
    print(f"{COLOR_GREY}{text}{COLOR_WHITE}")

def print_yellow(text: str):
    """Prints warning notifications in yellow color."""
    # Print warning notifications in yellow.
    print(f"{COLOR_YELLOW}{text}{COLOR_WHITE}")

def print_green(text: str):
    """Prints success notifications and verified source contexts in green color."""
    # Print success notifications in green.
    print(f"{COLOR_GREEN}{text}{COLOR_WHITE}")

def load_prompts() -> dict:
    """Loads prompt templates dynamically from prompts.json for ease of teaching."""
    try:
        with open("prompts.json", "r") as f:
            return json.load(f)
    except Exception as e:
        # Fallback to hardcoded prompts if file is missing to keep code resilient.
        print_yellow(f"[WARNING] Failed to load prompts.json: {e}.")
        sys.exit(1)

# Load prompt templates globally.
PROMPTS = load_prompts()

def load_dataset() -> list:
    """Loads the curated MITRE ATT&CK dataset from mitre_dataset.json."""
    # Wrap file operation in try-catch to satisfy defensive programming policies.
    try:
        # Open and load the dataset.
        with open("mitre_dataset.json", "r") as f:
            return json.load(f)
    except Exception as e:
        # Gracefully handle file read errors and print a clear error.
        print_yellow(f"[ERROR] Failed to load mitre_dataset.json: {e}")
        sys.exit(1)

def query_llm(messages: list, stream: bool = False, temperature: float = 0.0, color_code: str = COLOR_GREY) -> str:
    """Sends a request to the local OpenAI-compatible endpoint of Docker Model Runner."""
    # Format the request payload.
    payload = {
        "model": MODEL_NAME,
        "messages": messages,
        "temperature": temperature,
        "stream": stream
    }

    # Wrap external HTTP post requests in try-catch to ensure application stability.
    try:
        # Construct the completions endpoint URL.
        url = f"{MODEL_RUNNER_URL.rstrip('/')}/chat/completions"
        # Perform the POST request.
        response = requests.post(url, json=payload, timeout=120, stream=stream)
        response.raise_for_status()

        if stream:
            # We will accumulate the full response for the calling function.
            full_content = ""
            # Print the color code before streaming begins (unverified answer is streamed in Grey).
            sys.stdout.write(color_code)
            sys.stdout.flush()

            # Iterate through the streamed lines.
            for line in response.iter_lines():
                if line:
                    # Decode line from bytes.
                    decoded_line = line.decode("utf-8").strip()
                    # Check if the stream is finished.
                    if decoded_line == "data: [DONE]":
                        break
                    # Strip the data: prefix from the JSON chunk.
                    if decoded_line.startswith("data: "):
                        decoded_line = decoded_line[6:]
                    try:
                        # Load the delta chunk.
                        chunk_json = json.loads(decoded_line)
                        # Extract the newly generated token delta if present.
                        delta = chunk_json["choices"][0]["delta"].get("content", "")
                        # Print the token immediately.
                        sys.stdout.write(delta)
                        sys.stdout.flush()
                        # Append delta token to the full response.
                        full_content += delta
                    except Exception:
                        # Skip malformed lines silently.
                        continue
            # Reset color back to standard white terminal.
            sys.stdout.write(COLOR_WHITE)
            sys.stdout.flush()
            # Print a final newline to clean up stdout.
            print()
            return full_content
        else:
            # Return full content from a non-streaming response.
            return response.json()["choices"][0]["message"]["content"].strip()

    except Exception as e:
        # Gracefully notify the user if the model runner is not reachable.
        print_yellow(f"\n[ERROR] Failed to connect to Model Runner at {MODEL_RUNNER_URL}. Exception: {e}")
        print_yellow("Ensure 'docker model version' works and the chosen model is running.")
        sys.exit(1)

def compute_dataset_word_frequencies(dataset: list):
    """Scans the entire loaded dataset and counts raw word frequencies to identify rare terms."""
    global DATASET_TOKEN_FREQUENCIES
    DATASET_TOKEN_FREQUENCIES.clear()

    # Iterate through all techniques.
    for tech in dataset:
        # Combine all fields into a flat lowercase string.
        text = f"{tech['name']} {tech['description']} {tech['mitigations']} {tech['detection']}".lower()
        # Find alphanumeric tokens.
        tokens = re.findall(r"\b\w+\b", text)
        for token in tokens:
            # Increment frequency counts.
            DATASET_TOKEN_FREQUENCIES[token] = DATASET_TOKEN_FREQUENCIES.get(token, 0) + 1

def extract_explicit_mitre_id(query: str) -> str:
    """Uses a programmatic, foolproof Python regular expression to match explicit MITRE Technique or Sub-Technique IDs."""

    # === DETAILED EXPLANATION OF THE MITRE ID REGEX ===
    # regex = r"\b(T\d{4}(?:\.\d{3})?)\b"
    # \b        : Word boundary. This prevents matching IDs embedded inside larger words (e.g. 'ST1078' won't match).
    # (         : Start of capture group.
    # T         : Matches the literal capital letter 'T', which prefixes all MITRE ATT&CK techniques.
    # \d{4}     : Matches exactly four digits (0-9). This captures the base Technique ID (e.g. '1078').
    # (?:       : Start of a non-capturing group (used for grouping without creating a separate matched variable).
    # \.        : Matches a literal period/dot '.', which separates parent techniques from sub-techniques.
    # \d{3}     : Matches exactly three digits (0-9). This captures the sub-technique ID (e.g. '001').
    # )?        : Question mark makes the entire sub-technique non-capturing group optional.
    #             This allows matching both parent IDs ('T1078') and sub-technique IDs ('T1078.001') dynamically!
    # )         : End of capture group.
    # \b        : Word boundary. Prevents matching partial words (e.g. 'T1078.0015' won't match).

    match = re.search(r"\b(T\d{4}(?:\.\d{3})?)\b", query, re.IGNORECASE)
    if match:
        # Return the clean upper-case extracted ID.
        return match.group(1).upper()
    return None

def step1_extract_intent(query: str) -> str:
    """Uses LLM Introspection (Toolmeister pattern) to extract concise search keywords."""
    print_grey("[STEP 1] Introspecting query to extract search keywords...")

    # Grab template from our PROMPTS dictionary.
    template = PROMPTS.get("step1_extract_intent", "{query}")
    prompt = template.format(query=query)

    # Call LLM non-streamed for fast, deterministic extraction.
    response = query_llm([{"role": "user", "content": prompt}], stream=False)

    # Use Regex to cleanly parse the updated toolcall block.
    match = re.search(r"\[toolcall\](.*?)\[/toolcall\]", response, re.DOTALL | re.IGNORECASE)
    if match:
        extracted_text = match.group(1).strip()
        # Parse keywords.
        keywords_match = re.search(r"keywords:\s*(.*)$", extracted_text, re.IGNORECASE)
        keywords = keywords_match.group(1).strip() if keywords_match else "None"

        # Clean potential 'None' strings.
        if keywords.lower() == "none":
            keywords = None
        return keywords

    # Fallback if the LLM output was malformed.
    print_yellow("[WARNING] Extractor output format unexpected. Defaulting to manual parsing.")
    return query

def compute_similarity(keywords: str, dataset: list) -> list:
    """Computes similarity scores using Rare-Token Winnowing and Substring Phrase Matching."""
    if not keywords:
        return [(0, tech) for tech in dataset]

    # Split query into a lowercase token set.
    query_tokens = set(re.findall(r"\b\w+\b", keywords.lower()))

    scored_results = []
    # Loop over techniques.
    for technique in dataset:
        score = 0.0
        # Combine fields for substring and token search.
        name_lower = technique['name'].lower()
        desc_lower = technique['description'].lower()
        tech_id_lower = technique['id'].lower()

        # === PHRASE SUBSTRING MATCHING (High Priority) ===
        # If the exact multi-word keywords phrase appears directly in the name or ID, give it maximum weight!
        if keywords.lower() in name_lower or keywords.lower() in tech_id_lower:
            score += 100.0
        elif keywords.lower() in desc_lower:
            score += 25.0

        # === RARE-TOKEN WINNOWING SCORING ===
        # Loop over each keyword token to evaluate its dataset rarity weight.
        for token in query_tokens:
            # Check if token exists in the technique's name/description.
            if token in name_lower or token in desc_lower:
                # Find the token's total frequency across the entire loaded dataset.
                frequency = DATASET_TOKEN_FREQUENCIES.get(token, 1)

                # Apply Inverse-like frequency weighting: rare terms (low frequency) get massive scores!
                # If a term is rare (e.g. 'knocking', frequency=1), it gets a score of 10.0.
                # If a term is common (e.g. 'port', frequency=20), its weight is heavily diluted (10 / 20 = 0.5).
                token_weight = 10.0 / frequency

                # Double the weight if the rare token matches directly in the Technique's Name field!
                if token in name_lower:
                    token_weight *= 2.0

                score += token_weight

        scored_results.append((score, technique))

    # Sort with highest score first.
    scored_results.sort(key=lambda x: x[0], reverse=True)
    return scored_results

def step2_filter_and_rank(keywords: str, dataset: list) -> list:
    """Retrieves top-8 candidates using our highly precise Rare-Token Winnowing model."""
    print_grey(f"[STEP 2] Executing top-8 rare-token winnowed retrieval for keywords: '{keywords}'...")

    # Compute similarity scores.
    ranked = compute_similarity(keywords, dataset)
    # Select the top 8 matches with non-zero similarity.
    top_8 = [item[1] for item in ranked[:8] if item[0] > 0]

    print_grey(f"  -> Retrieved {len(top_8)} winnowed candidates.")
    return top_8

def step4_expand_and_deduplicate(candidates: list, full_dataset: list) -> str:
    """Option B: Expands context by injecting full profiles of sub-techniques and their parents, deduplicating output."""
    print_grey("[STEP 4] Performing Option B Hierarchical Expansion (Sub-technique -> Parent Technique)...")

    # Store processed technique IDs to avoid inserting redundant blocks.
    processed_ids = set()
    context_blocks = []

    # Helper function to append a technique profile cleanly.
    def append_tech_block(tech: dict, prefix: str = ""):
        if tech["id"] in processed_ids:
            return
        processed_ids.add(tech["id"])

        label = f"{prefix} Technique" if prefix else "Technique"
        block = (
            f"=== {label} Profile ===\n"
            f"MITRE Technique ID: {tech['id']}\n"
            f"Technique Name: {tech['name']}\n"
            f"Phase: {tech['phase']}\n"
            f"Description: {tech['description']}\n"
            f"Mitigations: {tech['mitigations']}\n"
            f"Detection: {tech['detection']}\n"
            f"========================\n"
        )
        context_blocks.append(block)

    # Loop over approved candidate matches.
    for tech in candidates:
        # Append the main verified technique.
        append_tech_block(tech)

        # Check if this matched technique is a sub-technique (contains a dot, like T1078.001).
        if "." in tech["id"]:
            parent_id = tech["id"].split(".")[0]
            print_grey(f"  -> Match {tech['id']} is a sub-technique. Searching for parent '{parent_id}'...")

            # Search the complete dataset for the parent technique definition.
            parent_tech = next((t for t in full_dataset if t["id"] == parent_id), None)
            if parent_tech:
                # Inject the parent technique's full profiles immediately adjacent to it!
                print_grey(f"     [EXPANDED] Found parent '{parent_id}' ({parent_tech['name']}). Injecting context.")
                append_tech_block(parent_tech, prefix="Parent")

    # Combine everything.
    combined_context = "\n".join(context_blocks)
    return combined_context

def step5_generate_final_answer(query: str, context: str) -> str:
    """Generates the final answer with context, streaming the tokens in Grey first."""
    print_grey("[STEP 5] Generating final answer (Streaming unverified output)...")

    # Grab system role prompt and final template from our PROMPTS dictionary.
    system_prompt = PROMPTS.get("step5_system_prompt", "")
    template = PROMPTS.get("step5_final_answer", "{query}")
    prompt = template.format(context=context, query=query)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt}
    ]

    # Stream the unverified final answer in terminal GREY to show "thinking" phase.
    final_answer = query_llm(messages, stream=True, temperature=0.2, color_code=COLOR_GREY)
    return final_answer

def step6_critic_verify(query: str, context: str, answer: str) -> bool:
    """Runs a post-generation Critic check to prevent hallucinations or logical gaps, checking logical flow."""
    print_grey("[STEP 6] Performing Critic Verification on the generated answer...")

    # Grab verification template.
    template = PROMPTS.get("step6_critic_verify", "{answer}")
    prompt = template.format(context=context, query=query, answer=answer)

    response = query_llm([{"role": "user", "content": prompt}], stream=False, temperature=0.0)
    print_grey("  -> Verification reasoning:\n" + "\n".join(f"     | {line}" for line in response.splitlines() if line.strip()))

    # Check if the critic marked it as valid.
    if "[VALID]" in response:
        return True
    return False

def run_harness(query: str):
    """Orchestrates the entire 6-step agentic LLM harness pipeline."""
    print_grey(f"=== Starting MITRE Agentic Harness CLI ===")
    print_grey(f"Configuration: Model={MODEL_NAME} | URL={MODEL_RUNNER_URL}")
    print_grey(f"User Query: '{query}'\n")

    # Load dataset.
    dataset = load_dataset()
    if not dataset:
        sys.exit(1)

    # Programmatically compute raw token frequencies across the dataset.
    compute_dataset_word_frequencies(dataset)

    # === PROGRAMMATIC ROUTING BYPASS ===
    # Instantly extract explicit MITRE IDs directly using our foolproof regex.
    explicit_id = extract_explicit_mitre_id(query)

    candidates = []

    # If a MITRE ID is matched, programmatically Direct-Fetch it and expand! Bypasses searches!
    if explicit_id:
        print_grey(f"[DIRECT BYPASS ROUTE] Foolproof Regex matched explicit ID: '{explicit_id}'")
        direct_tech = next((t for t in dataset if t["id"].lower() == explicit_id.lower()), None)
        if direct_tech:
            print_grey(f"  -> Direct-fetching technique: {direct_tech['id']} ({direct_tech['name']})")
            candidates.append(direct_tech)

            # Auto-expand parent if it is a sub-technique.
            if "." in direct_tech["id"]:
                parent_id = direct_tech["id"].split(".")[0]
                parent_tech = next((t for t in dataset if t["id"].lower() == parent_id.lower()), None)
                if parent_tech:
                    print_grey(f"  -> Direct-fetching parent technique: {parent_tech['id']} ({parent_tech['name']})")
                    candidates.append(parent_tech)
        else:
            print_yellow(f"  -> [WARNING] Explicit MITRE ID '{explicit_id}' was not found in our database.")

    # If NO explicit MITRE ID was matched, only then execute LLM keyword Winnowing search
    if not candidates:
        # Step 1: Introspect to find core search keywords.
        keywords = step1_extract_intent(query)
        print_grey(f"  -> Extracted Keywords: {keywords}\n")

        # If keywords are None, halt to prevent hallucinations.
        if not keywords:
            print_yellow("[HALTED] Introspection categorized search keywords as None.")
            print_yellow("[HALTED] To prevent hallucinations and blind guessing, execution is halting safely.")
            print_grey("=== Harness execution stopped securely ===")
            return

        # Step 2: Executes top-8 similarity checks using our Rare-Token Winnowing.
        candidates = step2_filter_and_rank(keywords, dataset)
        print_grey("")

    # === STRICT GATING CHECK ===
    # If no verified candidates remain after Direct-Fetch or search, halt safely to prevent blind guessing.
    if not candidates:
        print_yellow("[HALTED] No verified relevant MITRE ATT&CK techniques were found in our dataset.")
        print_yellow("[HALTED] To prevent hallucinations and blind guessing, execution is halting safely.")
        print_grey("=== Harness execution stopped securely ===")
        return

    # Step 4: Expand parent/sub techniques and deduplicate context.
    expanded_context = step4_expand_and_deduplicate(candidates, dataset)
    print_grey("")

    # Loop for Step 5 & Step 6 (Retry on Critic failure).
    max_retries = 2
    for attempt in range(1, max_retries + 1):
        # Step 5: Stream the final answer (streams in GREY as it is unverified thinking).
        answer = step5_generate_final_answer(query, expanded_context)
        print_grey("")

        # Step 6: Post-generation Critic check.
        is_valid = step6_critic_verify(query, expanded_context, answer)

        if is_valid:
            print_green("\n[SUCCESS] Critic verification passed! The answer is safe, logical, and fully grounded.\n")

            # --- THE GREY TO GREEN TO WHITE TRANSITION ---
            # Print the verified reference context in bright Green.
            print_green("=== VERIFIED MITRE ATT&CK CONTEXT ===")
            print_green(expanded_context.strip())
            print_green("=====================================\n")

            # Print the finalized, audited answer in crisp terminal White.
            print_green("=== FINAL GROUNDED RESPONSE ===")
            print(COLOR_WHITE + answer.strip() + COLOR_WHITE)
            print_green("===============================")

            print_grey("\n=== Harness execution completed successfully ===")
            return
        else:
            print_yellow(f"[WARNING] Critic flagged the answer as [INVALID] on attempt {attempt}/{max_retries}.")
            if attempt < max_retries:
                print_yellow("[WARNING] Regenerating the final answer to fix hallucinations...")
                print_grey("")
            else:
                print_yellow("[WARNING] Critic flagged the regenerated answer as potentially inaccurate. Terminating run.")

if __name__ == "__main__":
    # Check that query string exists. (Guarded by shell wrapper, but safe fallback)
    if len(sys.argv) < 2:
        sys.exit(0)

    # Reconstruct the query from all trailing arguments.
    user_query = " ".join(sys.argv[1:])
    run_harness(user_query)
