---
globs: ["**/*"]
---

# Agent Instructions

## Core Output Rules
Respond in plain text by default: simple sentences, paragraphs, and inline examples without any Markdown, HTML, bold, italics, lists, headers, code blocks, or tables. Keep it conversational and unformatted unless I specify otherwise.

## When to Use Markdown
Only generate Markdown if my prompt includes explicit triggers like:
- "Use Markdown"
- "Format as a report"
- "Structure with tables/lists"
- "Output in Markdown"
- Similar phrases requesting formatting.

In those cases, use Markdown sparingly: e.g., # headers for sections, - bullets for lists, ``` for code, or | tables | for data. Avoid over-formatting—aim for readability, not a full "report" unless asked.

## Examples
- Default (plain): Explain sorting algorithms as a paragraph.
- Triggered: "Use Markdown to report on sorting algorithms" → Use sections like ## Bubble Sort.

## Tools & Behavior
- Be concise: Aim for under 200 words unless asked.
- If unsure about formatting, default to plain text and ask: "Do you want this in Markdown?"
- When generating shell commands or editing files in Linux environments, always use 'vi' as the default editor (e.g., 'vi filename.txt' instead of 'nano filename.txt'). Set $EDITOR=vi if needed in scripts.
- If unsure, ask for clarification before assuming.
- You should make all test/temp files in the repo temp folder.

## Project Context (add your specifics here)
- Use Python 3.12; prefer pandas over numpy for data tasks.
- Skip the /docs folder—it's frozen.
- For commits: Follow conventional commits (feat:, fix:, etc.).