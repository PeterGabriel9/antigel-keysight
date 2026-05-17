#include "netem.h"
#include "http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <microhttpd.h>
#include <rte_lcore.h>

static struct MHD_Daemon *daemon_handle = NULL;

// single-file dashboard - Bootstrap + Chart.js from CDN, polls /api/stats every 500ms

static const char DASHBOARD[] =
"<!DOCTYPE html>"
"<html lang='en'>"
"<head>"
"<meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>NETEM Dashboard</title>"
"<link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap' rel='stylesheet'>"
"<script src='https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js'></script>"
"<style>"
"*{margin:0;padding:0;box-sizing:border-box}"
"body{background:#0a0e17;color:#c9d1d9;font-family:'Inter',system-ui,sans-serif;font-size:14px;padding:24px;min-height:100vh}"
".header{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px;padding-bottom:16px;border-bottom:1px solid #1c2333}"
".header h1{font-size:22px;font-weight:700;color:#e6edf3;letter-spacing:-.5px}"
".hdr-right{display:flex;align-items:center;gap:16px}"
".status{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:500}"
".dot{width:8px;height:8px;border-radius:50%;background:#3fb950;box-shadow:0 0 8px rgba(63,185,80,.5);animation:pulse 2s ease-in-out infinite}"
".dot.off{background:#f85149;box-shadow:0 0 8px rgba(248,81,73,.5)}"
"@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}"
".ts{color:#484f58;font-size:12px}"
".summary{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:24px}"
".scard{background:#111827;border:1px solid #1c2333;border-radius:10px;padding:16px 20px;transition:border-color .2s}"
".scard:hover{border-color:#30363d}"
".scard .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:#484f58;font-weight:600;margin-bottom:4px}"
".scard .val{font-size:26px;font-weight:700;font-variant-numeric:tabular-nums}"
".scard.c-rx .val{color:#58a6ff}"
".scard.c-tx .val{color:#3fb950}"
".scard.c-drop .val{color:#f85149}"
".scard.c-dup .val{color:#d29922}"
".scard.c-dly .val{color:#bc8cff}"
".grid2{display:grid;grid-template-columns:1fr 2fr;gap:16px;margin-bottom:24px}"
".panel{background:#111827;border:1px solid #1c2333;border-radius:10px;padding:20px}"
".ch-wrap{position:relative;height:180px}"
".stitle{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:#484f58;margin-bottom:14px}"
".hint{color:#30363d;font-weight:400;text-transform:none;letter-spacing:0;margin-left:10px;font-size:11px}"
"table{width:100%;border-collapse:separate;border-spacing:0}"
"th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:#484f58;font-weight:600;padding:8px 12px;border-bottom:1px solid #1c2333}"
"td{padding:10px 12px;border-bottom:1px solid rgba(28,35,51,.5);font-size:13px;vertical-align:middle}"
"tr:last-child td{border-bottom:none}"
"tbody tr{transition:background .15s}"
"tbody tr:hover td{background:rgba(88,166,255,.03)}"
".pq-id{font-weight:700;color:#e6edf3;font-size:14px}"
".pq-rule{font-family:'SF Mono','Fira Code',monospace;color:#79c0ff;font-size:12px;background:rgba(88,166,255,.08);padding:3px 10px;border-radius:4px;display:inline-block}"
".pq-pkts{font-variant-numeric:tabular-nums;color:#8b949e;font-weight:500}"
".cfg-wrap{display:flex;align-items:center;gap:6px}"
".cfg{width:64px;background:#0a0e17;color:#e6edf3;border:1px solid #1c2333;border-radius:6px;padding:5px 8px;text-align:center;font-family:'Inter',sans-serif;font-size:13px;font-weight:500;transition:all .2s}"
".cfg:focus{outline:none;border-color:#58a6ff;box-shadow:0 0 0 3px rgba(88,166,255,.15)}"
".cfg.f-drop:focus{border-color:#f85149;box-shadow:0 0 0 3px rgba(248,81,73,.15)}"
".cfg.f-dup:focus{border-color:#d29922;box-shadow:0 0 0 3px rgba(210,153,34,.15)}"
".cfg.f-dly:focus{border-color:#bc8cff;box-shadow:0 0 0 3px rgba(188,140,255,.15)}"
".cfg-unit{font-size:11px;color:#484f58;white-space:nowrap}"
".dq-wrap{display:flex;align-items:center;gap:8px}"
".dq-bar{width:80px;height:4px;border-radius:2px;background:#1c2333;overflow:hidden}"
".dq-fill{height:100%;border-radius:2px;background:linear-gradient(90deg,#bc8cff,#d29922);transition:width .4s ease}"
".dq-num{font-size:11px;color:#484f58;font-variant-numeric:tabular-nums}"
".row-drop{border-left:3px solid #f85149}"
".row-dup{border-left:3px solid #d29922}"
".row-dly{border-left:3px solid #bc8cff}"
".row-mix{border-left:3px solid #58a6ff}"
".row-none{border-left:3px solid transparent}"
".presets{display:flex;align-items:center;gap:10px;margin-bottom:20px;flex-wrap:wrap}"
".preset-btn{background:#111827;border:1px solid #1c2333;color:#8b949e;border-radius:6px;"
"padding:6px 14px;font-size:12px;font-weight:500;cursor:pointer;transition:all .2s;"
"font-family:'Inter',sans-serif}"
".preset-btn:hover{background:#1c2333;color:#e6edf3}"
".preset-drop:hover{border-color:#f85149;color:#f85149}"
".preset-dly:hover{border-color:#bc8cff;color:#bc8cff}"
".preset-dup:hover{border-color:#d29922;color:#d29922}"
".preset-chaos:hover{border-color:#58a6ff;color:#58a6ff}"
".toast{position:fixed;bottom:24px;right:24px;background:#161b22;border:1px solid #3fb950;color:#3fb950;padding:10px 20px;border-radius:8px;font-size:13px;font-weight:500;opacity:0;transform:translateY(10px);transition:all .3s;pointer-events:none;z-index:99}"
".toast.show{opacity:1;transform:translateY(0)}"
"@media(max-width:960px){.summary{grid-template-columns:repeat(2,1fr)}.grid2{grid-template-columns:1fr}}"
"</style>"
"</head>"
"<body>"
"<div class='header'>"
"  <h1>NETEM Dashboard</h1>"
"  <div class='hdr-right'>"
"    <div class='status'><div class='dot' id='dot'></div><span id='st'>Connected</span></div>"
"    <span class='ts' id='ts'></span>"
"  </div>"
"</div>"
"<div class='summary'>"
"  <div class='scard c-rx'><div class='lbl'>Total RX</div><div class='val' id='srx'>0</div></div>"
"  <div class='scard c-tx'><div class='lbl'>Total TX</div><div class='val' id='stx'>0</div></div>"
"  <div class='scard c-drop'><div class='lbl'>Dropped</div><div class='val' id='sdr'>0</div></div>"
"  <div class='scard c-dup'><div class='lbl'>Duplicated</div><div class='val' id='sdu'>0</div></div>"
"  <div class='scard c-dly'><div class='lbl'>Delayed</div><div class='val' id='sdl'>0</div></div>"
"</div>"
"<div class='grid2'>"
"  <div class='panel'>"
"    <div class='stitle'>Per-Port Statistics</div>"
"    <table><thead><tr><th>Port</th><th>RX</th><th>TX</th><th>Dropped</th><th>Duped</th></tr></thead>"
"    <tbody id='pt'></tbody></table>"
"  </div>"
"  <div class='panel'>"
"    <div class='stitle'>Throughput &mdash; packets / sec</div>"
"    <div class='ch-wrap'><canvas id='ch'></canvas></div>"
"  </div>"
"</div>"
"<div class='presets'>"
"  <span style='font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:#484f58'>Preset:</span>"
"  <button class='preset-btn' onclick='applyPreset(\"reset\")'>&#10003; Reset all</button>"
"  <button class='preset-btn preset-drop' onclick='applyPreset(\"loss30\")'>30% loss</button>"
"  <button class='preset-btn preset-dly' onclick='applyPreset(\"latency\")'>&#9200; 100ms delay</button>"
"  <button class='preset-btn preset-dup' onclick='applyPreset(\"dup\")'>Dup &times;3</button>"
"  <button class='preset-btn preset-chaos' onclick='applyPreset(\"chaos\")'>&#9760; Chaos</button>"
"</div>"
"<div class='panel'>"
"  <div class='stitle'>Profile Queues<span class='hint'>Click any value to edit, press Enter to apply</span></div>"
"  <table>"
"    <thead><tr>"
"      <th style='width:40px'>PQ</th>"
"      <th>Classification Rule</th>"
"      <th>Packets</th>"
"      <th>Drop Rate</th>"
"      <th>Dup Rate</th>"
"      <th>Delay</th>"
"      <th>Queue Depth</th>"
"    </tr></thead>"
"    <tbody id='pb'></tbody>"
"  </table>"
"</div>"
"<div class='toast' id='toast'>Configuration updated</div>"
"<script>"
"const N=60,rxd=Array(N).fill(0),txd=Array(N).fill(0);"
"const ch=new Chart(document.getElementById('ch'),{"
"  type:'line',"
"  data:{labels:Array(N).fill(''),"
"    datasets:["
"      {label:'RX',data:rxd,borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,.06)',"
"       tension:.3,fill:true,pointRadius:0,borderWidth:1.5},"
"      {label:'TX',data:txd,borderColor:'#3fb950',backgroundColor:'rgba(63,185,80,.06)',"
"       tension:.3,fill:true,pointRadius:0,borderWidth:1.5}"
"    ]},"
"  options:{animation:false,responsive:true,maintainAspectRatio:false,"
"    scales:{"
"      y:{beginAtZero:true,grid:{color:'#1c2333'},ticks:{color:'#484f58',font:{size:11},"
"         callback:v=>v>=1e6?(v/1e6).toFixed(1)+'M':v>=1e3?(v/1e3).toFixed(0)+'K':v}},"
"      x:{display:false}},"
"    plugins:{legend:{labels:{color:'#8b949e',boxWidth:8,padding:16,font:{size:11}}}}}});"
"let pr=0,pt2=0,first=true;"
"const fmt=n=>n>=1e9?(n/1e9).toFixed(2)+'G':n>=1e6?(n/1e6).toFixed(2)+'M':n>=1e3?(n/1e3).toFixed(1)+'K':String(n);"
"function showToast(){"
"  const t=document.getElementById('toast');"
"  t.classList.add('show');"
"  setTimeout(()=>t.classList.remove('show'),1500);"
"}"
"async function applyConfig(pq,field,val){"
"  const b={pq};b[field]=parseInt(val)||0;"
"  try{"
"    await fetch('/api/config',{method:'POST',"
"      headers:{'Content-Type':'application/json'},"
"      body:JSON.stringify(b)});"
"    showToast();"
"  }catch(e){}"
"}"
"function mkInp(pq,f,v,cls){"
"  return '<input id=\"i-'+pq+'-'+f+'\" class=\"cfg '+cls+'\" type=\"number\" min=\"0\" value=\"'+v+'\" '"
"    +'onchange=\"applyConfig('+pq+',\\''+f+'\\',this.value)\" '"
"    +'onkeydown=\"if(event.key===\\'Enter\\')this.blur()\">';"
"}"
"function rowClass(q){"
"  let n=0;"
"  if(q.drop_n>0)n++;"
"  if(q.dup_n>0)n++;"
"  if(q.delay_us>0)n++;"
"  if(n>1)return 'row-mix';"
"  if(q.drop_n>0)return 'row-drop';"
"  if(q.dup_n>0)return 'row-dup';"
"  if(q.delay_us>0)return 'row-dly';"
"  return 'row-none';"
"}"
/* create rows once — inputs are never re-rendered, so typing always works */
"function ensureRows(qs){"
"  const tb=document.getElementById('pb');"
"  qs.forEach(q=>{"
"    if(document.getElementById('row-'+q.id))return;"
"    const tr=document.createElement('tr');"
"    tr.id='row-'+q.id;"
"    tr.className=rowClass(q);"
"    tr.innerHTML="
"      '<td class=\"pq-id\">'+q.id+'</td>'"
"      +'<td><span class=\"pq-rule\">'+q.name+'</span></td>'"
"      +'<td class=\"pq-pkts\" id=\"c-pkt-'+q.id+'\">0</td>'"
"      +'<td><div class=\"cfg-wrap\">'+mkInp(q.id,'drop_n',q.drop_n,'f-drop')+'<span class=\"cfg-unit\">/ 10</span></div></td>'"
"      +'<td><div class=\"cfg-wrap\">'+mkInp(q.id,'dup_n',q.dup_n,'f-dup')+'<span class=\"cfg-unit\">/ 10</span></div></td>'"
"      +'<td><div class=\"cfg-wrap\">'+mkInp(q.id,'delay_us',q.delay_us,'f-dly')+'<span class=\"cfg-unit\">&micro;s</span></div></td>'"
"      +'<td><div class=\"dq-wrap\"><div class=\"dq-bar\"><div class=\"dq-fill\" id=\"c-dqf-'+q.id+'\" style=\"width:0%\">'"
"      +'</div></div><span class=\"dq-num\" id=\"c-dqn-'+q.id+'\">0</span></div></td>';"
"    tb.appendChild(tr);"
"  });"
"}"
/* update only the live cells — never touch focused inputs */
"function updateRows(qs){"
"  qs.forEach(q=>{"
"    const row=document.getElementById('row-'+q.id);"
"    if(row)row.className=rowClass(q);"
"    const pk=document.getElementById('c-pkt-'+q.id);"
"    if(pk)pk.textContent=fmt(q.pkt_count);"
"    const df=document.getElementById('c-dqf-'+q.id);"
"    if(df)df.style.width=Math.min(100,q.dq_depth/20.48)+'%';"
"    const dn=document.getElementById('c-dqn-'+q.id);"
"    if(dn)dn.textContent=q.dq_depth;"
"    ['drop_n','dup_n','delay_us'].forEach(f=>{"
"      const el=document.getElementById('i-'+q.id+'-'+f);"
"      if(el&&document.activeElement!==el)el.value=q[f];"
"    });"
"  });"
"}"
/* one-click preset — fires all 10 config POSTs in parallel */
"async function applyPreset(name){"
"  const P={"
"    reset:  {drop_n:0,dup_n:0,delay_us:0},"
"    loss30: {drop_n:3,dup_n:0,delay_us:0},"
"    latency:{drop_n:0,dup_n:0,delay_us:100000},"
"    dup:    {drop_n:0,dup_n:3,delay_us:0}"
"  };"
"  const reqs=[];"
"  for(let i=0;i<10;i++){"
"    const cfg=name==='chaos'"
"      ?{drop_n:Math.floor(Math.random()*6),dup_n:Math.floor(Math.random()*4),"
"        delay_us:Math.floor(Math.random()*5)*50000}"
"      :P[name];"
"    if(!cfg)continue;"
"    reqs.push(fetch('/api/config',{method:'POST',"
"      headers:{'Content-Type':'application/json'},"
"      body:JSON.stringify(Object.assign({pq:i},cfg))}));"
"  }"
"  await Promise.all(reqs).catch(()=>{});"
"}"
"async function poll(){"
"  try{"
"    const d=await fetch('/api/stats').then(r=>{if(!r.ok)throw 0;return r.json();});"
"    document.getElementById('dot').className='dot';"
"    document.getElementById('st').textContent='Connected';"
"    document.getElementById('ts').textContent=new Date().toLocaleTimeString();"
"    let trx=0,ttx=0,tdr=0,tdu=0,tdl=0;"
"    d.ports.forEach(p=>{trx+=p.rx;ttx+=p.tx;tdr+=p.dropped;tdu+=p.duplicated;tdl+=p.delayed});"
"    document.getElementById('srx').textContent=fmt(trx);"
"    document.getElementById('stx').textContent=fmt(ttx);"
"    document.getElementById('sdr').textContent=fmt(tdr);"
"    document.getElementById('sdu').textContent=fmt(tdu);"
"    document.getElementById('sdl').textContent=fmt(tdl);"
"    document.getElementById('pt').innerHTML=d.ports.map(p=>"
"      '<tr><td style=\"font-weight:600\">Port '+p.id+'</td><td style=\"color:#58a6ff\">'+fmt(p.rx)+'</td><td style=\"color:#3fb950\">'+fmt(p.tx)+'</td>'"
"      +'<td style=\"color:#f85149\">'+fmt(p.dropped)+'</td>'"
"      +'<td style=\"color:#d29922\">'+fmt(p.duplicated)+'</td></tr>'"
"    ).join('');"
"    if(!first){rxd.push(Math.max(0,trx-pr)*2);rxd.shift();"
"    txd.push(Math.max(0,ttx-pt2)*2);txd.shift();ch.update();}"
"    first=false;pr=trx;pt2=ttx;"
"    ensureRows(d.queues);"
"    updateRows(d.queues);"
"  }catch(e){"
"    document.getElementById('dot').className='dot off';"
"    document.getElementById('st').textContent='Offline';"
"  }"
"}"
"setInterval(poll,500);poll();"
"</script>"
"</body>"
"</html>";

// build the JSON blob for GET /api/stats

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

// parse POST /api/config body - just strstr + atoi, no fancy JSON lib needed

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


struct conn_state {
	char   body[4096];
	size_t len;
};


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

	/* first call for this connection */
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
		/* read body chunks until upload_data_size drops to 0 */
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
		/* done reading, apply it */
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
