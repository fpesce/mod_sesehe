/* Copyright 2006 Francois Pesce : francois.pesce (at) gmail (dot) com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>
#include <util_filter.h>
#include <apr_lib.h>
#include <apr_strings.h>

struct sesehe_srv_conf_t
{
    char *server_header;
    char *server_header_error;
    int server_header_drop;
    int server_header_error_drop;
};

typedef struct sesehe_srv_conf_t sesehe_srv_conf_t;

module AP_MODULE_DECLARE_DATA sesehe_module;

static void *sesehe_create_server_config(apr_pool_t *p, server_rec *s)
{
    sesehe_srv_conf_t *sesehe_conf = apr_pcalloc(p, sizeof(struct sesehe_srv_conf_t));

    sesehe_conf->server_header = NULL;
    sesehe_conf->server_header_error = NULL;
    sesehe_conf->server_header_drop = 0;
    sesehe_conf->server_header_error_drop = 0;

    return sesehe_conf;
}

static const char *sesehe_set_server_header(cmd_parms *cmd, void *config, const char *arg)
{
    sesehe_srv_conf_t *sesehe_conf = ap_get_module_config(cmd->server->module_config, &sesehe_module);

    sesehe_conf->server_header = apr_pstrdup(cmd->pool, arg);
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, cmd->server, "[%s] mod_sesehe server_header is %s",
		 __FUNCTION__, arg);

    return NULL;
}

static const char *sesehe_set_server_header_error(cmd_parms *cmd, void *config, const char *arg)
{
    sesehe_srv_conf_t *sesehe_conf = ap_get_module_config(cmd->server->module_config, &sesehe_module);

    sesehe_conf->server_header_error = apr_pstrdup(cmd->pool, arg);
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, cmd->server, "[%s] mod_sesehe server_header_error is %s",
		 __FUNCTION__, arg);

    return NULL;
}

static const char *sesehe_set_server_header_drop(cmd_parms *cmd, void *config, int arg)
{
    sesehe_srv_conf_t *sesehe_conf = ap_get_module_config(cmd->server->module_config, &sesehe_module);

    sesehe_conf->server_header_drop = arg;
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, cmd->server, "[%s] mod_sesehe server_header_drop is %i",
		 __FUNCTION__, arg);

    return NULL;
}

static const char *sesehe_set_server_header_error_drop(cmd_parms *cmd, void *config, int arg)
{
    sesehe_srv_conf_t *sesehe_conf = ap_get_module_config(cmd->server->module_config, &sesehe_module);

    sesehe_conf->server_header_error_drop = arg;
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, cmd->server, "[%s] mod_sesehe server_header_error_drop is %i",
		 __FUNCTION__, arg);

    return NULL;
}

static apr_status_t ap_sesehe_output_filter(ap_filter_t * f, apr_bucket_brigade * in)
{
    request_rec *r = f->r;
    server_rec *server = r->server;
    sesehe_srv_conf_t *sesehe_conf = ap_get_module_config(server->module_config, &sesehe_module);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, server, "sesehe_module: ap_sesehe_output_filter() %i %i",
		 sesehe_conf->server_header_error_drop, sesehe_conf->server_header_drop);

    /* That will force the keep of Server: header */
    if (PROXYREQ_NONE == r->proxyreq)
	f->r->proxyreq = PROXYREQ_NONE - 1;

    if (NULL != f->ctx) {
	if (0 == sesehe_conf->server_header_error_drop)
	    apr_table_setn(r->headers_out, "Server", sesehe_conf->server_header_error);
	else
	    apr_table_unset(r->headers_out, "Server");
    }
    else {
	if (0 == sesehe_conf->server_header_drop)
	    apr_table_setn(r->headers_out, "Server", sesehe_conf->server_header);
	else
	    apr_table_unset(r->headers_out, "Server");
    }

    /* remove ourselves from the filter chain */
    ap_remove_output_filter(f);

    /* send the data up the stack */
    return ap_pass_brigade(f->next, in);
}

static void ap_sesehe_insert_output_filter(request_rec *r)
{
    sesehe_srv_conf_t *sesehe_conf = ap_get_module_config(r->server->module_config, &sesehe_module);

    if (NULL != sesehe_conf->server_header || 1 == sesehe_conf->server_header_drop) {
	ap_add_output_filter("SESEHE_OUT", NULL, r, r->connection);
    }
}

static void ap_sesehe_insert_error_filter(request_rec *r)
{
    sesehe_srv_conf_t *sesehe_conf = ap_get_module_config(r->server->module_config, &sesehe_module);

    if (NULL != sesehe_conf->server_header_error || 1 == sesehe_conf->server_header_error_drop) {
	ap_add_output_filter("SESEHE_OUT", (void *) 0xdeadcafe, r, r->connection);
    }
}

static const command_rec sesehe_cmds[] = {
    AP_INIT_TAKE1("SecureServerHeader", sesehe_set_server_header, NULL, RSRC_CONF,
		  "The Server: header that you want to display all the time."),
    AP_INIT_TAKE1("SecureServerHeaderError", sesehe_set_server_header_error, NULL, RSRC_CONF,
		  "The Server: header that you want to display in case of error."),
    AP_INIT_FLAG("SecureServerHeaderDrop", sesehe_set_server_header_drop, NULL, RSRC_CONF,
		 "The Server: header is no more displayed when an error occurs if this value is \"On\"."),
    AP_INIT_FLAG("SecureServerHeaderErrorDrop", sesehe_set_server_header_error_drop, NULL, RSRC_CONF,
		 "The Server: header is no more displayed if this value is \"On\"."),
    {NULL}
};

static void sesehe_register_hooks(apr_pool_t *p)
{
    ap_hook_insert_filter(ap_sesehe_insert_output_filter, NULL, NULL, APR_HOOK_LAST);
    ap_hook_insert_error_filter(ap_sesehe_insert_error_filter, NULL, NULL, APR_HOOK_LAST);
    ap_register_output_filter("SESEHE_OUT", ap_sesehe_output_filter, NULL, AP_FTYPE_CONTENT_SET);
}

module AP_MODULE_DECLARE_DATA sesehe_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* dir config creater */
    NULL,			/* dir merger */
    sesehe_create_server_config,	/* server config */
    NULL,			/* merge server configs */
    sesehe_cmds,		/* command apr_table_t */
    sesehe_register_hooks	/* register hooks */
};
