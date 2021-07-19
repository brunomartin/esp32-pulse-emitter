/* Simple HTTP Server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <sys/param.h>
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "protocol_examples_common.h"
#include "esp_tls_crypto.h"
#include <esp_http_server.h>

#include "esp_task_wdt.h"

#include "driver/timer.h"

#include "driver/gpio.h"

#include "cJSON.h"

#include <math.h>

#define NOP() asm volatile ("nop") // 4.1ns
#define NOP2() asm volatile ("nop;nop") // 8.3ns
#define NOP5() asm volatile ("nop;nop;nop;nop;nop") // 20.1ns
#define NOP6() asm volatile ("nop;nop;nop;nop;nop;nop") // 25ns
#define NOP12() asm volatile ("nop;nop;nop;nop;nop;nop" \
    ";nop;nop;nop;nop;nop;nop") // 50ns

/* Settings for GPIO outputs */

#define GPIO_OUTPUT_IO_0    (gpio_num_t) 18
#define GPIO_OUTPUT_IO_1    (gpio_num_t) 19
#define GPIO_OUTPUT_PIN_SEL  ((1ULL<<GPIO_OUTPUT_IO_0) | (1ULL<<GPIO_OUTPUT_IO_1))

uint64_t pulses_sent = 0;
double last_rate_khz = 0;
int64_t last_total_duration_us = 0;

#define TIMESTAMPS_SIZE 2000
#define MEASUREMENT_SIZE 1000

/* structure for pulse task, timestamps are allocated 
  in main when application starts */
typedef struct task_parameters {
    uint64_t pulses;
    uint32_t period_us;
    uint32_t delay_us;
    uint64_t index;
    int64_t* timestamps;
} task_parameters_t;

task_parameters_t parameters;

volatile bool task_is_running = false;
volatile bool force_task_to_stop = false;

#define SCRATCH_BUFSIZE (10240)

typedef struct rest_server_context {
    char scratch[SCRATCH_BUFSIZE];
} rest_server_context_t;

rest_server_context_t rest_context;

/* A simple example that demonstrates how to create GET and POST
 * handlers for the web server.
 * One of the handlers start a task to toggle GPIO pins
 */

static const char *TAG = "example";

inline void send_pulse(const gpio_num_t gpio_num) {

    // Toggle pin using register
    GPIO.out_w1ts = (1 << gpio_num);
    NOP12(); // Wait about 6*1/240 us ~ 25ns
    GPIO.out_w1tc = (1 << gpio_num);

}

void vTaskCode( void * pvParameters )
{
    task_parameters_t* param = ((task_parameters_t *)(pvParameters));
    const uint64_t pulses = param->pulses;
    const uint32_t period_us = param->period_us;
    const uint32_t delay_us = param->delay_us;

    uint64_t count=-1, index=0;

    int64_t start_us = 0, end_us = 0, next_us = 0;
    int64_t duration_us;

    double rate_khz;

    task_is_running = true;
    force_task_to_stop = false;

    if(delay_us > period_us - 1) {
        ESP_LOGI(TAG,
            "delay_us (%" PRIu32 "us) > "
            "period_us (%" PRIu32 "us)"
            ", This program does not handle"
            " that for the moment", delay_us, period_us);
        task_is_running = false;
        vTaskDelete(NULL);
    } else if(pulses == 0) {
        ESP_LOGI(TAG, "No pulse to send");
        task_is_running = false;
        vTaskDelete(NULL);
    }

    ESP_LOGI(TAG, "Start !!!");
    ESP_LOGI(TAG, "pulses: %" PRIu64 "", pulses);
    ESP_LOGI(TAG, "period_us: %" PRIu32 "", period_us);
    ESP_LOGI(TAG, "delay_us: %" PRIu32 "", delay_us);

    if(delay_us > 0) {

        start_us = esp_timer_get_time();
        for (count=0;count<pulses;count++) {

            send_pulse(GPIO_OUTPUT_IO_0);

            // Wait requested delay
            next_us = start_us + count*period_us + delay_us;
            while((end_us = esp_timer_get_time()) < next_us) {}

            send_pulse(GPIO_OUTPUT_IO_1);

            // Wait the period
            next_us = start_us + (count+1)*period_us;
            while((end_us = esp_timer_get_time()) < next_us) {}

            param->timestamps[index] = end_us;
            param->index = index;
            pulses_sent++;

            index++;
            if(index == TIMESTAMPS_SIZE) index = 0;
            if(force_task_to_stop) break;

        }

    } else {

        start_us = esp_timer_get_time();
        for (count=0;count<pulses;count++) {

            send_pulse(GPIO_OUTPUT_IO_0);

            // Wait the period
            next_us = start_us + (count+1)*period_us;
            while((end_us = esp_timer_get_time()) < next_us) {}

            param->timestamps[index] = end_us;
            param->index = index;
            pulses_sent++;

            index++;
            if(index == TIMESTAMPS_SIZE) index = 0;
            if(force_task_to_stop) break;

        }

    }

    duration_us = end_us - start_us;
    ESP_LOGI(TAG, "duration_us: %" PRId64 "", duration_us);

    last_total_duration_us = duration_us;

    if(count != -1) {
        rate_khz = 1e3 * (count+1) / ((double) duration_us);
        ESP_LOGI(TAG, "rate_khz: %.3f", rate_khz);
        last_rate_khz = rate_khz;
    }

    task_is_running = false;
    vTaskDelete(NULL);
}

#if CONFIG_EXAMPLE_BASIC_AUTH

typedef struct {
    char    *username;
    char    *password;
} basic_auth_info_t;

#define HTTPD_401      "401 UNAUTHORIZED"           /*!< HTTP Response 401 */

static char *http_auth_basic(const char *username, const char *password)
{
    int out;
    char *user_info = NULL;
    char *digest = NULL;
    size_t n = 0;
    asprintf(&user_info, "%s:%s", username, password);
    if (!user_info) {
        ESP_LOGE(TAG, "No enough memory for user information");
        return NULL;
    }
    esp_crypto_base64_encode(NULL, 0, &n, (const unsigned char *)user_info, strlen(user_info));

    /* 6: The length of the "Basic " string
     * n: Number of bytes for a base64 encode format
     * 1: Number of bytes for a reserved which be used to fill zero
    */
    digest = calloc(1, 6 + n + 1);
    if (digest) {
        strcpy(digest, "Basic ");
        esp_crypto_base64_encode((unsigned char *)digest + 6, n, (size_t *)&out, (const unsigned char *)user_info, strlen(user_info));
    }
    free(user_info);
    return digest;
}

/* An HTTP GET handler */
static esp_err_t basic_auth_get_handler(httpd_req_t *req)
{
    char *buf = NULL;
    size_t buf_len = 0;
    basic_auth_info_t *basic_auth_info = req->user_ctx;

    buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
    if (buf_len > 1) {
        buf = calloc(1, buf_len);
        if (!buf) {
            ESP_LOGE(TAG, "No enough memory for basic authorization");
            return ESP_ERR_NO_MEM;
        }

        if (httpd_req_get_hdr_value_str(req, "Authorization", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Authorization: %s", buf);
        } else {
            ESP_LOGE(TAG, "No auth value received");
        }

        char *auth_credentials = http_auth_basic(basic_auth_info->username, basic_auth_info->password);
        if (!auth_credentials) {
            ESP_LOGE(TAG, "No enough memory for basic authorization credentials");
            free(buf);
            return ESP_ERR_NO_MEM;
        }

        if (strncmp(auth_credentials, buf, buf_len)) {
            ESP_LOGE(TAG, "Not authenticated");
            httpd_resp_set_status(req, HTTPD_401);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
            httpd_resp_send(req, NULL, 0);
        } else {
            ESP_LOGI(TAG, "Authenticated!");
            char *basic_auth_resp = NULL;
            httpd_resp_set_status(req, HTTPD_200);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            asprintf(&basic_auth_resp, "{\"authenticated\": true,\"user\": \"%s\"}", basic_auth_info->username);
            if (!basic_auth_resp) {
                ESP_LOGE(TAG, "No enough memory for basic authorization response");
                free(auth_credentials);
                free(buf);
                return ESP_ERR_NO_MEM;
            }
            httpd_resp_send(req, basic_auth_resp, strlen(basic_auth_resp));
            free(basic_auth_resp);
        }
        free(auth_credentials);
        free(buf);
    } else {
        ESP_LOGE(TAG, "No auth header received");
        httpd_resp_set_status(req, HTTPD_401);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Connection", "keep-alive");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
        httpd_resp_send(req, NULL, 0);
    }

    return ESP_OK;
}

static httpd_uri_t basic_auth = {
    .uri       = "/basic_auth",
    .method    = HTTP_GET,
    .handler   = basic_auth_get_handler,
};

static void httpd_register_basic_auth(httpd_handle_t server)
{
    basic_auth_info_t *basic_auth_info = calloc(1, sizeof(basic_auth_info_t));
    if (basic_auth_info) {
        basic_auth_info->username = CONFIG_EXAMPLE_BASIC_AUTH_USERNAME;
        basic_auth_info->password = CONFIG_EXAMPLE_BASIC_AUTH_PASSWORD;

        basic_auth.user_ctx = basic_auth_info;
        httpd_register_uri_handler(server, &basic_auth);
    }
}
#endif

/* An HTTP GET handler */
static esp_err_t hello_get_handler(httpd_req_t *req)
{
    char*  buf;
    size_t buf_len;

    /* Get header value string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
    if (buf_len > 1) {
        buf = (char*) malloc(buf_len);
        /* Copy null terminated value string into buffer */
        if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Host: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-2") + 1;
    if (buf_len > 1) {
        buf = (char*) malloc(buf_len);
        if (httpd_req_get_hdr_value_str(req, "Test-Header-2", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Test-Header-2: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-1") + 1;
    if (buf_len > 1) {
        buf = (char*) malloc(buf_len);
        if (httpd_req_get_hdr_value_str(req, "Test-Header-1", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Test-Header-1: %s", buf);
        }
        free(buf);
    }

    /* Read URL query string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1) {
        buf = (char*) malloc(buf_len);
        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found URL query => %s", buf);
            char param[32];
            /* Get value of expected key from query string */
            if (httpd_query_key_value(buf, "query1", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => query1=%s", param);
            }
            if (httpd_query_key_value(buf, "query3", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => query3=%s", param);
            }
            if (httpd_query_key_value(buf, "query2", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => query2=%s", param);
            }
        }
        free(buf);
    }

    /* Set some custom headers */
    httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
    httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");

    /* Send response with custom headers and body set as the
     * string passed in user context*/
    const char* resp_str = (const char*) req->user_ctx;

    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
        ESP_LOGI(TAG, "Request headers lost");
    }
    return ESP_OK;
}

void compute_statistics(const uint32_t* values, size_t size, uint32_t* value_min,
    uint32_t* value_max, double* value_mean, double* value_dev) {

    size_t index;
    int32_t value;

    *value_mean = 0;
    *value_min = values[0];
    *value_max = values[0];
    for(index=0;index<size;index++) {
        value = values[index];
        *value_min = value<*value_min?value:*value_min;
        *value_max = value>*value_max?value:*value_max;
        *value_mean += value;
    }
    *value_mean /= size;

    *value_dev = 0;
    for(index=0;index<size;index++) {
        value = values[index];
        *value_dev += (value-*value_mean)*(value-*value_mean);
    }
    *value_dev /= size;
    *value_dev = sqrt(*value_dev);
}

static esp_err_t statistics_get_handler(httpd_req_t *req)
{
    int64_t up_time_us;
    int up_time_s;
    char up_time_str[32];
 
    // Timestamps and duration are in us
    int64_t* wrapped_timestamps = NULL, *timestamps = NULL;
    uint32_t* durations = NULL;
    size_t size=0, wrap_size=0, index=0, duration_size=0;
    size_t read_index=0, write_index=0;
    uint32_t duration_min=0, duration_max=0;
    double duration_mean=0., duration_std=0., rate_khz = 0.;

    up_time_us = esp_timer_get_time();
    up_time_s = (int) (up_time_us/1e6);

    sprintf(up_time_str, "%d:%02d:%02d.%03d",
        up_time_s/3600,
        (up_time_s/60)%60,
        up_time_s%60,
        (int) (up_time_us/1e3)%1000);

    ESP_LOGI(TAG, "statistics_get_handler");
    ESP_LOGI(TAG, "To display from console:\n"
        "  watch -n 1 curl -s http://192.168.1.70/statistics");

    ESP_LOGI(TAG, "up_time_us: %" PRId64 "", up_time_us);
    ESP_LOGI(TAG, "last_total_duration_us: %" PRId64 "", last_total_duration_us);

    // Allocate memory and copy content of timestamps to it
    // Allocate twice for unwrap
    wrapped_timestamps = (int64_t*) calloc(2*MEASUREMENT_SIZE, sizeof(int64_t));
    memset(wrapped_timestamps, 0, 2*MEASUREMENT_SIZE*sizeof(int64_t));

    timestamps = parameters.timestamps;
    read_index = parameters.index - MEASUREMENT_SIZE;
    write_index = 0;
    size = MEASUREMENT_SIZE;

    // parameters.timestamps may be wrapping, parameters.index is the index of
    // the last written timestamp, parameters.timestamps shall be initialzed
    // to null
    if(parameters.index < MEASUREMENT_SIZE) {
        // Copy the last part of parameters.timestamps
        size = MEASUREMENT_SIZE - index;
        read_index = TIMESTAMPS_SIZE - size;
        memcpy(wrapped_timestamps + write_index, timestamps + read_index,
            size*sizeof(int64_t));
        
        // Update copy variables
        read_index = 0;
        write_index += size;
        size = MEASUREMENT_SIZE - size;
    }

    memcpy(wrapped_timestamps + write_index, timestamps + read_index,
            size*sizeof(int64_t));

    memset(wrapped_timestamps + MEASUREMENT_SIZE, 0, MEASUREMENT_SIZE*sizeof(int64_t));
    
    // Compute filled size by looking from the end
    // X X X X .... X X X 0 0 0 0 ... 0 0 0
    size = MEASUREMENT_SIZE;
    while(wrapped_timestamps[size-1] == 0 && size > 0) size--;

    // Compute statistics only if there is enough to compute
    // std dev (3 timestamps <=> 2 durations)
    if(size > 2) {
        // find index where timestamps wraps
        // + + + + .... + + + - - - - ... - - -
        for(wrap_size=1;wrap_size<size;wrap_size++) {
            if(wrapped_timestamps[wrap_size] - wrapped_timestamps[wrap_size-1] < 0) {
                break;
            }
        }

        // If there is no wrap, wrap_size shall be size
        //   and we shall do nothing
        timestamps = wrapped_timestamps;
        if(wrap_size < size) {
            // Copy the first part to the end and move pointer to the new start
            memcpy(wrapped_timestamps + size, wrapped_timestamps, wrap_size*sizeof(int64_t));
            timestamps = wrapped_timestamps + wrap_size;
        }

        // Allocate and compute durations
        duration_size = size-1;
        durations = (uint32_t*) calloc(duration_size, sizeof(uint32_t));

        for(index=0;index<duration_size;index++) {
            durations[index] = timestamps[index+1] - timestamps[index];
        }

        compute_statistics(durations, duration_size, &duration_min,
            &duration_max, &duration_mean, &duration_std);

        rate_khz = 1/duration_mean*1e3;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "pulses_sent", pulses_sent);
    cJSON_AddNumberToObject(root, "last_rate_khz", last_rate_khz);
    cJSON_AddNumberToObject(root, "up_time_us", up_time_us);
    cJSON_AddStringToObject(root, "up_time_str", up_time_str);
    cJSON_AddNumberToObject(root, "last_total_duration_us", last_total_duration_us);
    cJSON_AddNumberToObject(root, "duration_min_us", duration_min);
    cJSON_AddNumberToObject(root, "duration_max_us", duration_max);
    cJSON_AddNumberToObject(root, "duration_mean_us", duration_mean);
    cJSON_AddNumberToObject(root, "duration_std_us", duration_std);
    cJSON_AddNumberToObject(root, "rate_khz", rate_khz);
    cJSON_AddNumberToObject(root, "free_size", heap_caps_get_free_size(MALLOC_CAP_8BIT));
    cJSON_AddBoolToObject(root, "task_is_running", task_is_running);

// #define STATISTICS_DEBUG

#ifdef STATISTICS_DEBUG
    // Debug output
    cJSON_AddNumberToObject(root, "size", size);
    cJSON_AddNumberToObject(root, "wrap_size", wrap_size);
    cJSON_AddNumberToObject(root, "duration_size", duration_size);

    cJSON *array;

    array = cJSON_CreateArray();
    for(index=0;index<2*TIMESTAMPS_SIZE;index++) {
        cJSON_AddItemToArray(array, cJSON_CreateNumber(wrapped_timestamps[index]));
    }
    cJSON_AddItemToObject(root, "wrapped_timestamps", array);
    
    array = cJSON_CreateArray();
    for(index=0;index<size;index++) {
        cJSON_AddItemToArray(array, cJSON_CreateNumber(timestamps[index]));
    }
    cJSON_AddItemToObject(root, "timestamps", array);

    array = cJSON_CreateArray();
    for(index=0;index<duration_size;index++) {
        cJSON_AddItemToArray(array, cJSON_CreateNumber(durations[index]));
    }
    cJSON_AddItemToObject(root, "durations", array);

#endif // STATISTICS_DEBUG

    // Free memories
    free(durations);
    free(wrapped_timestamps);

    const char *json_str = cJSON_Print(root);
    httpd_resp_sendstr(req, json_str);
    cJSON_Delete(root);

    httpd_resp_set_type(req, "application/json");

    return ESP_OK;
}

/* An HTTP POST handler */
static esp_err_t action_post_handler(httpd_req_t *req)
{
    ESP_LOGI(TAG, "action_post_handler");
    ESP_LOGI(TAG, "To start from console:\n"
        "  curl -X POST http://192.168.1.70/action -d '{\"pulses\": 5e6, \"period_us\": 2, \"delay_us\": 1}'");

    uint64_t pulses = 6*1e6;
    uint32_t period_us = 1;
    uint32_t delay_us = 0;

    int total_len = req->content_len;
    int cur_len = 0;
    char *buf = ((rest_server_context_t *)(req->user_ctx))->scratch;
    int received = 0;
    if (total_len >= SCRATCH_BUFSIZE) {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "content too long");
        return ESP_FAIL;
    }
    while (cur_len < total_len) {
        received = httpd_req_recv(req, buf + cur_len, total_len);
        if (received <= 0) {
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to post control value");
            return ESP_FAIL;
        }
        cur_len += received;
    }
    buf[total_len] = '\0';

    cJSON *root = cJSON_Parse(buf);

    if(cJSON_HasObjectItem(root, "pulses")) {
        pulses = cJSON_GetObjectItem(root, "pulses")->valueint;
    }

    if(cJSON_HasObjectItem(root, "period_us")) {
        period_us = cJSON_GetObjectItem(root, "period_us")->valueint;
    }

    if(cJSON_HasObjectItem(root, "delay_us")) {
        delay_us = cJSON_GetObjectItem(root, "delay_us")->valueint;
    }

    cJSON_Delete(root);

    root = cJSON_CreateObject();

    /* Force task to stop and wait */
    force_task_to_stop = true;
    while(task_is_running) {}

    /* Start the task */
    ESP_LOGI(TAG, "Start new task");

    if(period_us < 2) {
        period_us = 2;
        ESP_LOGI(TAG, "Force period to %" PRIu32 "us", delay_us);
    } else if(delay_us > 0) {
        ESP_LOGI(TAG, "period: %" PRIu32 "us", period_us);
    }

    if(delay_us > period_us - 1) {
        delay_us = period_us - 1;
        ESP_LOGI(TAG, "Force delay to %" PRIu32 "us", delay_us);
    } else if(delay_us > 0) {
        ESP_LOGI(TAG, "delay: %" PRIu32 "us", delay_us);
    }

    parameters.pulses = pulses;
    parameters.period_us = period_us;
    parameters.delay_us = delay_us;

    memset(parameters.timestamps, 0, TIMESTAMPS_SIZE*sizeof(int64_t));

    TaskHandle_t xHandle;
    xTaskCreatePinnedToCore( vTaskCode, "Send pulse task", 2048, &parameters,
        (configMAX_PRIORITIES - 1) | portPRIVILEGE_BIT, &xHandle, 1 );
    configASSERT( xHandle );

    cJSON_AddStringToObject(root, "result", "ok");
    cJSON_AddNumberToObject(root, "pulses", pulses);
    cJSON_AddNumberToObject(root, "period_us", period_us);
    cJSON_AddNumberToObject(root, "delay_us", delay_us);

    const char *json_str = cJSON_Print(root);
    httpd_resp_sendstr(req, json_str);
    cJSON_Delete(root);

    return ESP_OK;

}

static const httpd_uri_t hello = {
    .uri       = "/hello",
    .method    = HTTP_GET,
    .handler   = hello_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = (void*) "Hello World!"
};

static const httpd_uri_t anne_cecile = {
    .uri       = "/anne-cecile",
    .method    = HTTP_GET,
    .handler   = hello_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = (void*) "Salut Amour!"
};

static const httpd_uri_t bruno = {
    .uri       = "/bruno",
    .method    = HTTP_GET,
    .handler   = hello_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = (void*) "Salut Bruno!"
};

static const httpd_uri_t solene = {
    .uri       = "/solene",
    .method    = HTTP_GET,
    .handler   = hello_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = (void*) "Salut Solène!"
};

static const httpd_uri_t statistics = {
    .uri       = "/statistics",
    .method    = HTTP_GET,
    .handler   = statistics_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = (void*) "Statistics!"
};

static const httpd_uri_t action = {
    .uri       = "/action",
    .method    = HTTP_POST,
    .handler   = action_post_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = &rest_context
};

/* An HTTP POST handler */
static esp_err_t echo_post_handler(httpd_req_t *req)
{
    char buf[100];
    int ret, remaining = req->content_len;

    while (remaining > 0) {
        /* Read the data for the request */
        if ((ret = httpd_req_recv(req, buf,
                        MIN(remaining, sizeof(buf)))) <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                /* Retry receiving if timeout occurred */
                continue;
            }
            return ESP_FAIL;
        }

        /* Send back the same data */
        httpd_resp_send_chunk(req, buf, ret);
        remaining -= ret;

        /* Log data received */
        ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
        ESP_LOGI(TAG, "%.*s", ret, buf);
        ESP_LOGI(TAG, "====================================");
    }

    // End response
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t echo = {
    .uri       = "/echo",
    .method    = HTTP_POST,
    .handler   = echo_post_handler,
    .user_ctx  = NULL
};

/* This handler allows the custom error handling functionality to be
 * tested from client side. For that, when a PUT request 0 is sent to
 * URI /ctrl, the /hello and /echo URIs are unregistered and following
 * custom error handler http_404_error_handler() is registered.
 * Afterwards, when /hello or /echo is requested, this custom error
 * handler is invoked which, after sending an error message to client,
 * either closes the underlying socket (when requested URI is /echo)
 * or keeps it open (when requested URI is /hello). This allows the
 * client to infer if the custom error handler is functioning as expected
 * by observing the socket state.
 */
esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (strcmp("/hello", req->uri) == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/hello URI is not available");
        /* Return ESP_OK to keep underlying socket open */
        return ESP_OK;
    } else if (strcmp("/echo", req->uri) == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/echo URI is not available");
        /* Return ESP_FAIL to close underlying socket */
        return ESP_FAIL;
    }
    /* For any other URI send 404 and close socket */
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
    return ESP_FAIL;
}

/* An HTTP PUT handler. This demonstrates realtime
 * registration and deregistration of URI handlers
 */
static esp_err_t ctrl_put_handler(httpd_req_t *req)
{
    char buf;
    int ret;

    if ((ret = httpd_req_recv(req, &buf, 1)) <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }

    if (buf == '0') {
        /* URI handlers can be unregistered using the uri string */
        ESP_LOGI(TAG, "Unregistering /hello and /echo URIs");
        httpd_unregister_uri(req->handle, "/hello");
        httpd_unregister_uri(req->handle, "/echo");
        httpd_unregister_uri(req->handle, "/anne-cecile");
        httpd_unregister_uri(req->handle, "/bruno");
        httpd_unregister_uri(req->handle, "/solene");
        httpd_unregister_uri(req->handle, "/statistics");
        httpd_unregister_uri(req->handle, "/action");
        /* Register the custom error handler */
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, http_404_error_handler);
    }
    else {
        ESP_LOGI(TAG, "Registering /hello and /echo URIs");
        httpd_register_uri_handler(req->handle, &hello);
        httpd_register_uri_handler(req->handle, &echo);
        httpd_register_uri_handler(req->handle, &anne_cecile);
        httpd_register_uri_handler(req->handle, &bruno);
        httpd_register_uri_handler(req->handle, &solene);
        httpd_register_uri_handler(req->handle, &statistics);
        httpd_register_uri_handler(req->handle, &action);
        /* Unregister custom error handler */
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, NULL);
    }

    /* Respond with empty body */
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t ctrl = {
    .uri       = "/ctrl",
    .method    = HTTP_PUT,
    .handler   = ctrl_put_handler,
    .user_ctx  = NULL
};

static httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {

        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &hello);
        httpd_register_uri_handler(server, &echo);
        httpd_register_uri_handler(server, &ctrl);
        httpd_register_uri_handler(server, &anne_cecile);
        httpd_register_uri_handler(server, &bruno);
        httpd_register_uri_handler(server, &solene);
        httpd_register_uri_handler(server, &statistics);
        httpd_register_uri_handler(server, &action);
        #if CONFIG_EXAMPLE_BASIC_AUTH
        httpd_register_basic_auth(server);
        #endif
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

static void stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    httpd_stop(server);
}

static void disconnect_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server) {
        ESP_LOGI(TAG, "Stopping webserver");
        stop_webserver(*server);
        *server = NULL;
    }
}

static void connect_handler(void* arg, esp_event_base_t event_base,
                            int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server == NULL) {
        ESP_LOGI(TAG, "Starting webserver");
        *server = start_webserver();
    }
}

#ifdef __cplusplus
extern "C" {
#endif

void app_main(void)
{
    static httpd_handle_t server = NULL;

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_task_wdt_init(600, false));

    parameters.index = 0;
    parameters.timestamps = (int64_t*) calloc(TIMESTAMPS_SIZE, sizeof(int64_t));

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

    /* Register event handlers to stop the server when Wi-Fi or Ethernet is disconnected,
     * and re-start it upon connection.
     */
#ifdef CONFIG_EXAMPLE_CONNECT_WIFI
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_WIFI
#ifdef CONFIG_EXAMPLE_CONNECT_ETHERNET
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_ETHERNET

    /* Start the server for the first time */
    server = start_webserver();
    ESP_LOGI(TAG, "Webserver started");

    ESP_LOGI(TAG, "Setting GPIO outputs");

    gpio_config_t io_conf;
    //disable interrupt
    io_conf.intr_type = GPIO_INTR_DISABLE;
    //set as output mode
    io_conf.mode = GPIO_MODE_OUTPUT;
    //bit mask of the pins that you want to set,e.g.GPIO18/19
    io_conf.pin_bit_mask = GPIO_OUTPUT_PIN_SEL;
    //disable pull-down mode
    io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
    //disable pull-up mode
    io_conf.pull_up_en = GPIO_PULLUP_DISABLE;
    //configure GPIO with the given settings
    gpio_config(&io_conf);

}

#ifdef __cplusplus
}
#endif
