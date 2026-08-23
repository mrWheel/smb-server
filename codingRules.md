## Change Scope
Make the smallest edit that satisfies the request. Do not refactor, reformat, or touch unrelated files or table/log formatting. If a working rule or behaviour already exists, never remove it while fixing something else — if a fix requires touching working code, ask first.

### You Do the Edit
When the user reports a bug, apply the fix in the code yourself. Do not hand back instructions for the user to edit files manually.

## Code Conventions

### Verify Before Guessing (ESP-IDF / Typst)
Do not invent API names, headers, component versions, or language constructs. Before using an ESP-IDF header/API or a Typst function, grep the local SDK/source or fetch the official docs to confirm it exists. Compile after every single edit rather than batching speculative changes.

# Coding Rules

- AI assistant requirement: Always read this file first and apply all rules at the start of every new chat/session.

- Use the Allman coding style.
- Use lowerCamelCase naming for variables and functions.
- Use 2 spaces for indentation.
- Place comments above variables and functions using the format: `//-- `
- Write all comments in English.
- Keep `README.md` always in English.
- Keep all user-facing and internal code messages in English.
- Keep `Aandewiel` exactly as written in names; never convert it to lowerCamelCase.
- In C/C++ code, prefer `std::string` instead of Arduino `String` where possible.
- In C/C++ code, prefer `Serial.printf()` and `snprintf()` where possible.
- Never remove empty lines or skip code sections.
- For code changes and suggestions, never show only a few lines: always provide complete functions. For new code, clearly indicate where it should be placed by showing the existing lines before and after.