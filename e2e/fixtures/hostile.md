# Hostile document

<script>window.__hvSandboxScriptRan = true;</script>

<img src="x" onerror="window.__hvSandboxHandlerRan = true;" alt="broken on purpose">

<a href="javascript:window.__hvSandboxJavascriptUrl = true">a javascript: link</a>

<iframe src="https://example.com/nested"></iframe>

<style>body { display: none; }</style>

Ordinary prose after the hostile markup, so a renderer that dropped everything
can be told apart from one that sanitized correctly.
