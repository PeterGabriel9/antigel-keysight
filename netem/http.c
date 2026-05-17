#include "netem.h"
#include "http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <microhttpd.h>
#include <rte_lcore.h>

static struct MHD_Daemon *daemon_handle = NULL;

/* ------------------------------------------------------------------ */
/* embedded HTML dashboard                                              */
/* single-file app: bootstrap + chart.js from CDN, vanilla JS polling  */
/* ------------------------------------------------------------------ */

static const char DASHBOARD[] =
"<!DOCTYPE html><html lang='en'><head>"
"<meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>NETEM Dashboard</title>"
"<link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css'>"
"<script src='https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js'></script>"
"<style>"
"body{background:#0d1117;color:#e6edf3;font-family:monospace;font-size:.9rem}"
".card{background:#161b22;border:1px solid #30363d;border-radius:6px}"
".table{color:#e6edf3}.table td,.table th{border-color:#30363d;vertical-align:middle}"
"input.cfg{width:80px;background:#0d1117;color:#58a6ff;border:1px solid #30363d;"
"border-radius:4px;padding:2px 6px;text-align:center;font-family:monospace}"
"input.cfg:focus{outline:none;border-color:#58a6ff;box-shadow:0 0 0 2px rgba(88,166,255,.25)}"
".live{color:#3fb950}.dead{color:#f85149}"
".dbar{height:6px;border-radius:3px;background:#21262d;width:80px}"
".dbar-fill{height:100%;border-radius:3px;background:#d29922;transition:width .3s}"
"code{color:#79c0ff}"
"</style></head>"
"<body class='p-3'>"

/* header */
"<div class='d-flex align-items-center gap-3 mb-3'>"
"<h5 class='m-0'>&#9889; NETEM Dashboard</h5>"
"<span id='st' class='live fw-bold'>&#9679; live</span>"
"<small class='text-muted ms-auto' id='ts'></small>"
"</div>"

/* top row: port stats + throughput chart */
"<div class='row g-3 mb-3'>"
"<div class='col-xl-4'>"
"<div class='card p-3 h-100'>"
"<div class='text-muted small mb-2 text-uppercase'>Port Statistics</div>"
"<table class='table table-sm mb-0' id='pt'>"
"<thead><tr><th>Port</th><th>RX</th><th>TX</th>"
"<th class='text-danger'>Dropped</th><th class='text-warning'>Duped</th></tr></thead>"
"<tbody></tbody></table>"
"</div></div>"
"<div class='col-xl-8'>"
"<div class='card p-3 h-100'>"
"<div class='text-muted small mb-2 text-uppercase'>Throughput &mdash; packets / sec</div>"
"<canvas id='ch' height='85'></canvas>"
"</div></div></div>"

/* PQ table */
"<div class='card p-3'>"
"<div class='text-muted small mb-2 text-uppercase'>"
"Profile Queues &mdash; <span class='text-secondary'>edit fields inline, press Enter to apply</span>"
"</div>"
"<div class='table-responsive'>"
"<table class='table table-sm mb-0'>"
"<thead><tr>"
"<th>PQ</th><th>Pattern</th><th>Packets</th><th>Delay queue</th>"
"<th>Drop / 10</th><th>Dup / 10</th><th>Delay &mu;s</th>"
"</tr></thead>"
"<tbody id='pb'></tbody>"
"</table></div></div>"

/* ---- JS ---- */
"<script>"

/* chart setup */
"const N=60,rxd=Array(N).fill(0),txd=Array(N).fill(0);"
"const ch=new Chart(document.getElementById('ch'),{"
"  type:'line',"
"  data:{labels:Array(N).fill(''),"
"    datasets:["
"      {label:'RX',data:rxd,borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,.08)',"
"       tension:.3,fill:true,pointRadius:0,borderWidth:1.5},"
"      {label:'TX',data:txd,borderColor:'#3fb950',backgroundColor:'rgba(63,185,80,.08)',"
"       tension:.3,fill:true,pointRadius:0,borderWidth:1.5}"
"    ]},"
"  options:{animation:false,"
"    scales:{"
"      y:{beginAtZero:true,grid:{color:'#21262d'},ticks:{color:'#8b949e',"
"         callback:v=>v>=1e6?(v/1e6).toFixed(1)+'M':v>=1e3?(v/1e3).toFixed(0)+'K':v}},"
"      x:{display:false}},"
"    plugins:{legend:{labels:{color:'#e6edf3',boxWidth:10,padding:16}}}}});"

/* helpers */
"let pr=0,pt2=0;"
"const fmt=n=>n>=1e9?(n/1e9).toFixed(2)+'G':n>=1e6?(n/1e6).toFixed(2)+'M':n>=1e3?(n/1e3).toFixed(1)+'K':String(n);"

/* send config change to server */
"async function applyConfig(pq,field,val){"
"  const b={pq};b[field]=parseInt(val)||0;"
"  fetch('/api/config',{method:'POST',"
"    headers:{'Content-Type':'application/json'},"
"    body:JSON.stringify(b)}).catch(()=>{});"
"}"

/* build an editable input cell — skip re-render if currently focused */
"function inp(pq,f,v){"
"  const id='i-'+pq+'-'+f;"
"  const el=document.getElementById(id);"
"  if(el&&document.activeElement===el)return el.outerHTML;"
"  return '<input id=\"'+id+'\" class=\"cfg\" type=\"number\" min=\"0\" value=\"'+v+'\" '"
"    +'onchange=\"applyConfig('+pq+',\\''+f+'\\',this.value)\" '"
"    +'onkeydown=\"if(event.key===\\'Enter\\')this.blur()\">';"
"}"

/* row background hint */
"function rc(q){"
"  if(q.drop_n>0&&q.dup_n===0&&q.delay_us===0)return 'style=\"background:rgba(248,81,73,.05)\"';"
"  if(q.dup_n>0&&q.drop_n===0)return 'style=\"background:rgba(210,153,34,.05)\"';"
"  if(q.delay_us>0)return 'style=\"background:rgba(88,166,255,.05)\"';"
"  return '';"
"}"

/* main poll loop */
"async function poll(){"
"  try{"
"    const d=await fetch('/api/stats').then(r=>{if(!r.ok)throw 0;return r.json();});"
"    document.getElementById('st').textContent='\\u25cf live';"
"    document.getElementById('st').className='live fw-bold';"
"    document.getElementById('ts').textContent=new Date().toLocaleTimeString();"

"    document.querySelector('#pt tbody').innerHTML=d.ports.map(p=>"
"      '<tr><td>port '+p.id+'</td><td>'+fmt(p.rx)+'</td><td>'+fmt(p.tx)+'</td>'"
"      +'<td class=\"text-danger\">'+fmt(p.dropped)+'</td>'"
"      +'<td class=\"text-warning\">'+fmt(p.duplicated)+'</td></tr>'"
"    ).join('');"

"    const tr=d.ports.reduce((s,p)=>s+p.rx,0);"
"    const tt=d.ports.reduce((s,p)=>s+p.tx,0);"
"    rxd.push(Math.max(0,tr-pr)*2);rxd.shift();"
"    txd.push(Math.max(0,tt-pt2)*2);txd.shift();"
"    pr=tr;pt2=tt;ch.update();"

"    document.getElementById('pb').innerHTML=d.queues.map(q=>"
"      '<tr '+rc(q)+'>'"
"      +'<td><b>'+q.id+'</b></td>'"
"      +'<td><code>'+q.name+'</code></td>'"
"      +'<td>'+fmt(q.pkt_count)+'</td>'"
"      +'<td><div class=\"dbar\"><div class=\"dbar-fill\" style=\"width:'"
"        +Math.min(100,q.dq_depth/20.48)+'%\"></div></div>'"
"        +'<small class=\"text-muted ms-1\">'+q.dq_depth+'</small></td>'"
"      +'<td>'+inp(q.id,'drop_n',q.drop_n)+'</td>'"
"      +'<td>'+inp(q.id,'dup_n',q.dup_n)+'</td>'"
"      +'<td>'+inp(q.id,'delay_us',q.delay_us)+'</td>'"
"      +'</tr>'"
"    ).join('');"

"  }catch(e){"
"    document.getElementById('st').textContent='\\u25cf offline';"
"    document.getElementById('st').className='dead fw-bold';"
"  }"
"}"
"setInterval(poll,500);poll();"
"</script></body></html>";

/* ------------------------------------------------------------------ */
/* JSON building                                                        */
/* ------------------------------------------------------------------ */

static void
build_stats_json(char *buf, size_t bufsz)
{
	int n = 0;

	n += snprintf(buf + n, bufsz - n, "{\"ports\":[");
	for (int p = 0; p < NB_PORTS; p++) {
		n += snprintf(buf + n, bufsz - n,
			"%s{\"id\":%d,\"rx\":%"PRIu64",\"tx\":%"PRIu64","
			"\"dropped\":%"PRIu64",\"duplicated\":%"PRIu64",\"delayed\":%"PRIu64"}",
			p ? "," : "", p,
			port_statistics[p].rx,
			port_statistics[p].tx,
			port_statistics[p].dropped,
			port_statistics[p].duplicated,
			port_statistics[p].delayed);
	}

	n += snprintf(buf + n, bufsz - n, "],\"queues\":[");
	for (int q = 0; q < NUM_PQ; q++) {
		n += snprintf(buf + n, bufsz - n,
			"%s{\"id\":%d,\"name\":\"%s\","
			"\"pkt_count\":%"PRIu64",\"dq_depth\":%u,"
			"\"drop_n\":%u,\"dup_n\":%u,\"delay_us\":%"PRIu64"}",
			q ? "," : "", q,
			pq_configs[q].name,
			pq_agg[q].pkt_count,
			pq_agg[q].dq_count,
			pq_configs[q].drop_n,
			pq_configs[q].dup_n,
			pq_configs[q].delay_us);
	}
	n += snprintf(buf + n, bufsz - n, "]}");
}

/* ------------------------------------------------------------------ */
/* JSON config parsing — no extra deps, just strstr + atoi             */
/* expected body: {"pq":N,"drop_n":N} etc, one field at a time        */
/* ------------------------------------------------------------------ */

static void
parse_config_update(const char *json)
{
	char *p;
	int   pq_id = -1;

	p = strstr(json, "\"pq\"");
	if (p) { p = strchr(p, ':'); if (p) pq_id = atoi(p + 1); }
	if (pq_id < 0 || pq_id >= NUM_PQ) return;

	p = strstr(json, "\"drop_n\"");
	if (p) { p = strchr(p, ':'); if (p) pq_configs[pq_id].drop_n = (uint32_t)atoi(p + 1); }

	p = strstr(json, "\"dup_n\"");
	if (p) { p = strchr(p, ':'); if (p) pq_configs[pq_id].dup_n = (uint32_t)atoi(p + 1); }

	p = strstr(json, "\"delay_us\"");
	if (p) { p = strchr(p, ':'); if (p) pq_configs[pq_id].delay_us = (uint64_t)strtoull(p + 1, NULL, 10); }
}

/* ------------------------------------------------------------------ */
/* MHD helpers                                                          */
/* ------------------------------------------------------------------ */

static enum MHD_Result
respond(struct MHD_Connection *conn, unsigned int code,
        const char *content_type, const char *body, size_t body_len)
{
	struct MHD_Response *resp = MHD_create_response_from_buffer(
		body_len, (void *)body, MHD_RESPMEM_MUST_COPY);
	MHD_add_response_header(resp, "Content-Type", content_type);
	MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
	enum MHD_Result r = MHD_queue_response(conn, code, resp);
	MHD_destroy_response(resp);
	return r;
}

/* ------------------------------------------------------------------ */
/* per-connection state for collecting POST body                        */
/* ------------------------------------------------------------------ */

struct conn_state {
	char   body[4096];
	size_t len;
};

/* ------------------------------------------------------------------ */
/* request handler                                                      */
/* ------------------------------------------------------------------ */

static enum MHD_Result
handle_request(void *cls,
               struct MHD_Connection *conn,
               const char *url,
               const char *method,
               const char *version,
               const char *upload_data,
               size_t *upload_data_size,
               void **con_cls)
{
	(void)cls; (void)version;

	/* first call for this connection: allocate per-connection state */
	if (*con_cls == NULL) {
		struct conn_state *cs = calloc(1, sizeof(*cs));
		if (!cs) return MHD_NO;
		*con_cls = cs;
		return MHD_YES;
	}

	struct conn_state *cs = *con_cls;

	/* ---- GET / ---- */
	if (strcmp(method, "GET") == 0 && strcmp(url, "/") == 0) {
		return respond(conn, MHD_HTTP_OK, "text/html",
		               DASHBOARD, strlen(DASHBOARD));
	}

	/* ---- GET /api/stats ---- */
	if (strcmp(method, "GET") == 0 && strcmp(url, "/api/stats") == 0) {
		static char json[8192];
		build_stats_json(json, sizeof(json));
		return respond(conn, MHD_HTTP_OK, "application/json",
		               json, strlen(json));
	}

	/* ---- POST /api/config ---- */
	if (strcmp(method, "POST") == 0 && strcmp(url, "/api/config") == 0) {
		/* accumulate body across multiple upload_data calls */
		if (*upload_data_size > 0) {
			size_t take = *upload_data_size;
			if (cs->len + take >= sizeof(cs->body) - 1)
				take = sizeof(cs->body) - cs->len - 1;
			memcpy(cs->body + cs->len, upload_data, take);
			cs->len += take;
			cs->body[cs->len] = '\0';
			*upload_data_size = 0;
			return MHD_YES;
		}
		/* all body received — apply the config update */
		parse_config_update(cs->body);
		return respond(conn, MHD_HTTP_OK, "application/json",
		               "{\"ok\":true}", 11);
	}

	return respond(conn, MHD_HTTP_NOT_FOUND, "text/plain", "not found", 9);
}

static void
request_done(void *cls, struct MHD_Connection *conn,
             void **con_cls, enum MHD_RequestTerminationCode toe)
{
	(void)cls; (void)conn; (void)toe;
	free(*con_cls);
	*con_cls = NULL;
}

/* ------------------------------------------------------------------ */
/* start / stop                                                         */
/* ------------------------------------------------------------------ */

void
http_server_start(int port)
{
	daemon_handle = MHD_start_daemon(
		MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_THREAD_PER_CONNECTION,
		(uint16_t)port,
		NULL, NULL,
		handle_request, NULL,
		MHD_OPTION_NOTIFY_COMPLETED, request_done, NULL,
		MHD_OPTION_END);

	if (daemon_handle)
		printf("Web dashboard:  http://localhost:%d\n", port);
	else
		fprintf(stderr, "WARNING: could not start HTTP server on port %d\n", port);
}

void
http_server_stop(void)
{
	if (daemon_handle) {
		MHD_stop_daemon(daemon_handle);
		daemon_handle = NULL;
	}
}
