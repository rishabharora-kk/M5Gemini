#include "agent_link.h"
#include "agent_certs.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_sntp.h"
#include "mbedtls/base64.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mjson.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <atomic>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <vector>

static const char* TAG = "AGENT";
static const char* kRelay = "https://ntfy.sh";
static const int kJobSecs = 300; // give up on a task after this long
static const int kPollMs = 2500;
static const size_t kMaxResult = 1800; // what we hand back to the model; it speaks a summary anyway

static struct
{
    bool ready = false;
    uint8_t keyUp[32];
    uint8_t keyDown[32];
    std::string topicUp;
    std::string topicDown;
    agent_result_cb cb = nullptr;
} s_a;

static std::atomic<bool> s_busy{false};
static std::string s_task;

// ─── base64url (no padding) ───
static std::string b64url_encode(const uint8_t* d, size_t n)
{
    size_t cap = (n + 2) / 3 * 4 + 4;
    std::string o(cap, '\0');
    size_t w = 0;
    mbedtls_base64_encode((unsigned char*)&o[0], cap, &w, d, n);
    o.resize(w);
    for (char& c : o)
    {
        if (c == '+')
            c = '-';
        else if (c == '/')
            c = '_';
    }
    while (!o.empty() && o.back() == '=')
        o.pop_back();
    return o;
}

static bool b64url_decode(const char* s, size_t n, std::vector<uint8_t>& out)
{
    std::string t(s, n);
    for (char& c : t)
    {
        if (c == '-')
            c = '+';
        else if (c == '_')
            c = '/';
    }
    while (t.size() % 4)
        t.push_back('=');
    out.resize(t.size() / 4 * 3);
    size_t w = 0;
    if (mbedtls_base64_decode(out.data(), out.size(), &w, (const unsigned char*)t.data(), t.size()) != 0)
        return false;
    out.resize(w);
    return true;
}

// ─── HKDF-SHA256, salt "claudeputer-v1": every output we need fits one 32-byte block ───
static void hkdf(const uint8_t secret[32], const char* info, uint8_t* out, size_t len)
{
    static const char kSalt[] = "claudeputer-v1";
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t prk[32], msg[24], t[32];
    mbedtls_md_hmac(md, (const unsigned char*)kSalt, sizeof(kSalt) - 1, secret, 32, prk);
    size_t il = strlen(info);
    memcpy(msg, info, il);
    msg[il] = 1;
    mbedtls_md_hmac(md, prk, 32, msg, il + 1, t);
    memcpy(out, t, len);
}

static void derive(const uint8_t secret[32])
{
    uint8_t tu[16], td[16];
    hkdf(secret, "topic-up", tu, 16);
    hkdf(secret, "topic-down", td, 16);
    hkdf(secret, "key-up", s_a.keyUp, 32);
    hkdf(secret, "key-down", s_a.keyDown, 32);
    s_a.topicUp = "cp-" + b64url_encode(tu, 16);
    s_a.topicDown = "cp-" + b64url_encode(td, 16);
}

// ─── AES-256-GCM envelope: base64url(nonce[12] || ciphertext || tag[16]), AAD = topic ───
static bool seal(const uint8_t key[32], const std::string& topic, const std::string& plain, std::string& body)
{
    std::vector<uint8_t> buf(12 + plain.size() + 16);
    esp_fill_random(buf.data(), 12);
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    bool ok = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256) == 0 &&
              mbedtls_gcm_crypt_and_tag(&g,
                                        MBEDTLS_GCM_ENCRYPT,
                                        plain.size(),
                                        buf.data(),
                                        12,
                                        (const unsigned char*)topic.data(),
                                        topic.size(),
                                        (const unsigned char*)plain.data(),
                                        buf.data() + 12,
                                        16,
                                        buf.data() + 12 + plain.size()) == 0;
    mbedtls_gcm_free(&g);
    if (ok)
        body = b64url_encode(buf.data(), buf.size());
    return ok;
}

static bool open_msg(const uint8_t key[32], const std::string& topic, const char* body, size_t n, std::string& plain)
{
    std::vector<uint8_t> raw;
    if (!b64url_decode(body, n, raw) || raw.size() < 12 + 16)
        return false;
    size_t ct = raw.size() - 12 - 16;
    plain.assign(ct, '\0');
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    bool ok = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256) == 0 &&
              mbedtls_gcm_auth_decrypt(&g,
                                       ct,
                                       raw.data(),
                                       12,
                                       (const unsigned char*)topic.data(),
                                       topic.size(),
                                       raw.data() + 12 + ct,
                                       16,
                                       raw.data() + 12,
                                       (unsigned char*)&plain[0]) == 0;
    mbedtls_gcm_free(&g);
    return ok;
}

// ─── pairing ───
bool agent_init(const std::string& code, agent_result_cb on_result)
{
    s_a.ready = false;
    if (code.size() != 47 || code.compare(0, 4, "cp1-") != 0)
        return false;
    std::vector<uint8_t> secret;
    if (!b64url_decode(code.c_str() + 4, 43, secret) || secret.size() != 32)
        return false;
    derive(secret.data());
    s_a.cb = on_result;
    s_a.ready = true;
    ESP_LOGI(TAG, "paired, topic %s", s_a.topicUp.c_str());
    return true;
}

// ─── time: messages carry the clock, and the connector drops any that are more than 15 minutes off ───
static bool ensure_time()
{
    if (time(nullptr) > 1700000000)
        return true;
    if (!esp_sntp_enabled())
    {
        esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
        esp_sntp_setservername(0, "pool.ntp.org");
        esp_sntp_init();
    }
    for (int i = 0; i < 80 && time(nullptr) <= 1700000000; i++)
        vTaskDelay(pdMS_TO_TICKS(100));
    return time(nullptr) > 1700000000;
}

// ─── relay ───
static esp_http_client_handle_t http_new(const std::string& url, esp_http_client_method_t method)
{
    esp_http_client_config_t c = {};
    c.url = url.c_str();
    c.method = method;
    c.cert_pem = kRelayRootCAs;
    c.timeout_ms = 15000;
    c.buffer_size = 1024;
    return esp_http_client_init(&c);
}

static bool publish(const std::string& body)
{
    esp_http_client_handle_t h = http_new(std::string(kRelay) + "/" + s_a.topicUp, HTTP_METHOD_POST);
    if (!h)
        return false;
    esp_http_client_set_header(h, "X-Firebase", "no");
    esp_http_client_set_header(h, "Content-Type", "text/plain");
    esp_http_client_set_post_field(h, body.c_str(), (int)body.size());
    esp_err_t e = esp_http_client_perform(h);
    int status = esp_http_client_get_status_code(h);
    esp_http_client_cleanup(h);
    if (e != ESP_OK || status != 200)
        ESP_LOGW(TAG, "publish failed: %s http=%d", esp_err_to_name(e), status);
    return e == ESP_OK && status == 200;
}

struct Job
{
    std::string id;
    std::string result;
    std::string lastId;
    bool done = false;
    bool ok = false;
};

static char s_line[5400]; // one ntfy JSON line: a sealed message is at most ~4 KB
static char s_msg[4300];
static char s_text[2900];

static void handle_line(Job& j, const char* line, size_t len)
{
    char ev[16];
    if (mjson_get_string(line, (int)len, "$.event", ev, sizeof(ev)) < 0 || strcmp(ev, "message") != 0)
        return;
    char id[48];
    if (mjson_get_string(line, (int)len, "$.id", id, sizeof(id)) > 0)
        j.lastId = id;
    int n = mjson_get_string(line, (int)len, "$.message", s_msg, sizeof(s_msg));
    if (n <= 0)
        return;
    std::string plain;
    if (!open_msg(s_a.keyDown, s_a.topicDown, s_msg, (size_t)n, plain))
        return; // not ours, or forged: drop silently

    const char* p = plain.c_str();
    int pl = (int)plain.size();
    char k[12], jid[12];
    if (mjson_get_string(p, pl, "$.k", k, sizeof(k)) < 0)
        return;
    if (mjson_get_string(p, pl, "$.j", jid, sizeof(jid)) < 0 || j.id != jid)
        return;
    double ts = 0;
    mjson_get_number(p, pl, "$.ts", &ts);
    if (ts < (double)time(nullptr) - 900 || ts > (double)time(nullptr) + 120)
        return;

    if (strcmp(k, "part") == 0)
    {
        if (mjson_get_string(p, pl, "$.text", s_text, sizeof(s_text)) > 0)
            j.result += s_text;
    }
    else if (strcmp(k, "done") == 0)
    {
        int ok = 0;
        mjson_get_bool(p, pl, "$.ok", &ok);
        j.ok = ok != 0;
        j.done = true;
    }
    else if (strcmp(k, "error") == 0)
    {
        if (mjson_get_string(p, pl, "$.text", s_text, sizeof(s_text)) > 0)
            j.result = s_text;
        j.ok = false;
        j.done = true;
    }
    // ack and step messages need no action
}

// One poll of the down topic. Feeds each NDJSON line to handle_line.
static bool poll(Job& j, const std::string& since)
{
    std::string url = std::string(kRelay) + "/" + s_a.topicDown + "/json?poll=1&since=" + since;
    esp_http_client_handle_t h = http_new(url, HTTP_METHOD_GET);
    if (!h)
        return false;
    bool ok = false;
    if (esp_http_client_open(h, 0) == ESP_OK)
    {
        esp_http_client_fetch_headers(h);
        if (esp_http_client_get_status_code(h) == 200)
        {
            ok = true;
            char chunk[512];
            size_t ll = 0;
            bool overflow = false;
            int r;
            while ((r = esp_http_client_read(h, chunk, sizeof(chunk))) > 0)
            {
                for (int i = 0; i < r; i++)
                {
                    if (chunk[i] == '\n')
                    {
                        if (ll && !overflow)
                            handle_line(j, s_line, ll);
                        ll = 0;
                        overflow = false;
                    }
                    else if (ll < sizeof(s_line) - 1)
                        s_line[ll++] = chunk[i];
                    else
                        overflow = true;
                }
            }
            if (ll && !overflow)
                handle_line(j, s_line, ll);
        }
    }
    esp_http_client_cleanup(h);
    return ok;
}

static void finish(bool ok, std::string text)
{
    if (text.size() > kMaxResult)
        text.resize(kMaxResult);
    ESP_LOGI(TAG, "task finished ok=%d %u chars", ok, (unsigned)text.size());
    if (s_a.cb)
        s_a.cb(text, ok);
    s_busy = false;
    vTaskDelete(nullptr);
}

static void job_task(void*)
{
    Job j;
    char id[9];
    snprintf(id, sizeof(id), "%08x", (unsigned)esp_random());
    j.id = id;

    if (!ensure_time())
        finish(false, "the Cardputer could not get the time, so it cannot reach the agent");
    long ts = (long)time(nullptr);

    std::string task = s_task.substr(0, 1900);
    std::vector<char> q(task.size() * 6 + 16);
    mjson_snprintf(q.data(), q.size(), "%Q", task.c_str());
    std::string plain = "{\"v\":1,\"k\":\"ask\",\"j\":\"" + j.id + "\",\"n\":1,\"ts\":" + std::to_string(ts) +
                        ",\"text\":" + q.data() + "}";
    std::string body;
    if (!seal(s_a.keyUp, s_a.topicUp, plain, body))
        finish(false, "encryption failed");
    if (!publish(body) && !publish(body))
        finish(false, "could not reach the relay");

    std::string since = std::to_string(ts - 5);
    for (int waited = 0; waited < kJobSecs * 1000 && !j.done; waited += kPollMs)
    {
        vTaskDelay(pdMS_TO_TICKS(kPollMs));
        poll(j, since);
        if (!j.lastId.empty())
            since = j.lastId;
    }
    if (!j.done)
        finish(false, "the agent did not answer in time. Is the connector running on the PC?");
    finish(j.ok, j.result.empty() ? (j.ok ? "done" : "failed") : j.result);
}

std::string agent_submit(const std::string& task)
{
    if (!s_a.ready)
        return "no agent is paired";
    if (task.empty())
        return "empty task";
    bool expected = false;
    if (!s_busy.compare_exchange_strong(expected, true))
        return "busy: another task is still running";
    s_task = task;
    if (xTaskCreate(job_task, "agent_job", 12 * 1024, nullptr, 4, nullptr) != pdPASS)
    {
        s_busy = false;
        return "out of memory";
    }
    return "";
}
