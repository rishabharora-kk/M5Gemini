// Link to a Claude Code agent on your PC through an ntfy relay, speaking the Kloudputer agent protocol v1
// (connector/PROTOCOL.md in the kloudputer repo): AES-256-GCM messages on topics derived from a pairing code.
#pragma once

#include <string>

typedef void (*agent_result_cb)(const std::string& text, bool ok);

// Derives the keys from a pairing code ("cp1-..."). False if the code is empty or malformed.
bool agent_init(const std::string& pairing_code, agent_result_cb on_result);

// Starts one task in the background. Returns "" on success, else why not (busy, not paired, no Wi-Fi time).
// on_result runs later, from the agent's own task, with the agent's final report.
std::string agent_submit(const std::string& task);
