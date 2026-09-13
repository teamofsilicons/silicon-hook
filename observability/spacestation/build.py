#!/usr/bin/env python3
"""Build Hook Space Windows from credential-free query and view definitions."""
import json
from pathlib import Path
ROOT = Path(__file__).parent
FIELDS = {'source':'String','step':'String','outcome':'String','operation':'String','route':'String','method':'String','status':'Nullable(Int32)','duration_ms':'Nullable(Float64)','progress':'Nullable(Int32)','version':'String','trace_id':'String'}
ALIASES = {'step':'event','duration_ms':'latency_ms','trace_id':'request_id'}
# Deduplicate the durable exporter's at-least-once writes by Hook event ID.
BASE = "SELECT record.event.event_id::String AS event_id, any(record.recorded_at_ms::Float64) AS at_ms, " + ', '.join(f"any(record.event.{k}::{v}) AS {ALIASES.get(k,k)}" for k,v in FIELDS.items()) + ", greatest(0., toFloat64(min(registered_ts_ms)) - at_ms) AS lag_ms FROM siliconhook WHERE record.service::String = 'silicon-hook' AND record.environment_id::String = '00000000-0000-0000-0000-000000000000' AND record.recorded_at_ms::Float64 >= toUnixTimestamp64Milli(now64()) - 86400000 AND record.event.event_id::String != '' AND record.event.step::String != 'verification' GROUP BY event_id"
FROM = f'FROM ({BASE})'
TRACE = f'SELECT at_ms,source,event,outcome,operation,route,status,latency_ms,request_id {FROM}'
def query(select, tail=''): return f'SELECT {select} {FROM} {tail}'
def col(key,label,kind='text'): return dict(key=key,label=label,kind=kind)
def table(key,title,note,columns): return dict(rows_key=key,id=key,title=title,note=note,columns=[col(*c) for c in columns])
def card(label,key,detail,tone='neutral',unit='',group='totals'): return dict(label=label,key=key,detail=detail,tone=tone,unit=unit,group=group)
RECENT=[('at_ms','Recorded','time'),('source','Source'),('event','Step'),('outcome','Outcome'),('operation','Operation'),('status','Status','status'),('latency_ms','Duration','ms'),('request_id','Trace ID','trace')]
REQUEST="source = 'backend' AND event = 'request' AND status >= 100 AND route NOT IN ('/healthz','/readyz','/api/version','/api/v1/version')"
DELIVERY="source IN ('daemon','client') AND event IN ('connect','subscribe','deliver','ack','refresh')"
VIEWS=[dict(slug='overview',name='Hook Overview',subtitle='Traffic signals, failures and telemetry freshness',queries={
 'totals':query("toInt32(count()) AS events,toInt32(uniqExact(source)) AS sources,toInt32(countIf(outcome='failed')) AS failures,quantileExact(0.95)(lag_ms) AS lag_ms"),
 'sources':query("source,toInt32(count()) AS events,toInt32(countIf(outcome='failed')) AS failures,toFloat64(max(at_ms)) AS last_seen_ms,quantileExact(0.95)(lag_ms) AS lag_ms",'GROUP BY source ORDER BY events DESC'),
 'trend':query('toFloat64(intDiv(toInt64(at_ms),3600000)*3600000) AS at_ms,toInt32(count()) AS value','GROUP BY at_ms ORDER BY at_ms'),
 'worker':query("event,version,outcome,toInt32(count()) AS events,avg(latency_ms) AS avg_ms,toInt32(max(progress)) AS failed_tasks,toFloat64(max(at_ms)) AS last_seen_ms","WHERE source='worker' GROUP BY event,version,outcome ORDER BY last_seen_ms DESC LIMIT 20"),
 'issues':TRACE+" WHERE outcome='failed' ORDER BY at_ms DESC LIMIT 35"},
 cards=[card('Recorded events','events','Unique production event IDs'),card('Reporting sources','sources','Observed in the last 24 hours'),card('Failed events','failures','Includes expected request refusals','danger'),card('P95 arrival delay','lag_ms','Event creation to first station receipt',unit='ms')],
 tables=[table('sources','Source freshness','Last seen is telemetry freshness, not service availability.',[('source','Source'),('events','Events','number'),('failures','Failures','number'),('lag_ms','P95 arrival','ms'),('last_seen_ms','Last seen','time')]),table('worker','Worker maintenance','Signals are maintenance runs, not webhook deliveries. Failed tasks is the maximum per run.',[('event','Step'),('version','Version'),('outcome','Outcome'),('events','Runs','number'),('avg_ms','Average','ms'),('failed_tasks','Max failed tasks','number'),('last_seen_ms','Last seen','time')]),table('issues','Recent failed events','Latest 35 failures. A failure event is not necessarily a unique incident.',RECENT)]),
 dict(slug='requests',name='Hook Requests',subtitle='Application traffic, response codes and route latency',queries={
 'totals':query('toInt32(count()) AS requests,toInt32(countIf(status>=400 AND status<500)) AS client_errors,toInt32(countIf(status>=500)) AS server_errors,quantileExact(0.95)(latency_ms) AS p95_ms','WHERE '+REQUEST),
 'routes':query('method,route,toInt32(count()) AS requests,toInt32(countIf(status>=400 AND status<500)) AS client_errors,toInt32(countIf(status>=500)) AS server_errors,avg(latency_ms) AS avg_ms,quantileExact(0.95)(latency_ms) AS p95_ms','WHERE '+REQUEST+' GROUP BY method,route ORDER BY requests DESC LIMIT 45'),
 'recent': f'SELECT at_ms,method,route,status,latency_ms,request_id {FROM} WHERE {REQUEST} ORDER BY at_ms DESC LIMIT 40'},
 cards=[card('App requests','requests','Health, readiness and version probes excluded'),card('Client errors · 4xx','client_errors','Includes expected authorization refusals','warn'),card('Server errors · 5xx','server_errors','Completed backend request failures','danger'),card('P95 latency','p95_ms','Across all included requests',unit='ms')],
 tables=[table('routes','Route performance','Top 45 routes. Nullable latency remains unknown when absent.',[('method','Method'),('route','Route'),('requests','Requests','number'),('client_errors','4xx','number'),('server_errors','5xx','number'),('avg_ms','Average','ms'),('p95_ms','P95','ms')]),table('recent','Recent requests','Latest 40 completed requests. Route templates contain no private URL values.',[('at_ms','Recorded','time'),('method','Method'),('route','Route'),('status','Status','status'),('latency_ms','Latency','ms'),('request_id','Trace ID','trace')])]),
 dict(slug='deliveries',name='Hook Deliveries',subtitle='Client delivery attempts, retries and acknowledgements',queries={
 'totals':query("toInt32(countIf(event='deliver' AND outcome='succeeded')) AS delivered,toInt32(countIf(event='deliver' AND outcome='failed')) AS failed,toInt32(countIf(outcome='retrying')) AS retries,toInt32(countIf(event='ack' AND outcome='succeeded')) AS acknowledged",'WHERE '+DELIVERY),
 'activity':query('source,event,outcome,toInt32(count()) AS events,avg(latency_ms) AS avg_ms,toFloat64(max(at_ms)) AS last_seen_ms','WHERE '+DELIVERY+' GROUP BY source,event,outcome ORDER BY events DESC LIMIT 45'),
 'recent':TRACE+' WHERE '+DELIVERY+' ORDER BY at_ms DESC LIMIT 40'},
 cards=[card('Successful attempts','delivered','Client-reported deliver succeeded'),card('Failed attempts','failed','Client-reported deliver failed','danger'),card('Retry signals','retries','Across delivery lifecycle steps','warn'),card('Acknowledgements','acknowledged','Client-reported ack succeeded')],
 tables=[table('activity','Delivery lifecycle','Attempts and signals are not unique webhook totals. Data appears when updated clients send telemetry.',[('source','Source'),('event','Step'),('outcome','Outcome'),('events','Signals','number'),('avg_ms','Average','ms'),('last_seen_ms','Last seen','time')]),table('recent','Recent delivery activity','No recorded activity means no telemetry in this range, not proof that no deliveries occurred.',RECENT)]),
 dict(slug='clients',name='Hook Web & CLI',subtitle='Browser pages, command outcomes and client versions',queries={
 'totals':query("toInt32(countIf(source='web' AND event='page_view')) AS views,toInt32(countIf(source='cli' AND event='command' AND outcome IN ('succeeded','failed'))) AS commands,toInt32(countIf(source IN ('cli','daemon','client') AND outcome='failed')) AS failures,toInt32(countIf(source='web' AND event='error')) AS errors"),
 'pages':query("operation,toInt32(count()) AS views,toFloat64(max(at_ms)) AS last_seen_ms","WHERE source='web' AND event='page_view' GROUP BY operation ORDER BY views DESC LIMIT 20"),
 'activity':query('source,event,operation,outcome,version,toInt32(count()) AS events,toFloat64(max(at_ms)) AS last_seen_ms',"WHERE source IN ('web','cli','daemon','client') GROUP BY source,event,operation,outcome,version ORDER BY events DESC LIMIT 60")},
 cards=[card('Page views','views','Browser-reported views, not unique visitors'),card('CLI commands','commands','Succeeded and failed completions'),card('Native failures','failures','CLI, daemon and client signals','danger'),card('Browser errors','errors','Reported error events','danger')],
 tables=[table('pages','Browser pages','Only allowlisted page names are collected.',[('operation','Page'),('views','Views','number'),('last_seen_ms','Last seen','time')]),table('activity','Client activity','Top 60 source, step, operation, outcome and version groups. No command arguments are collected.',[('source','Source'),('event','Step'),('operation','Operation'),('outcome','Outcome'),('version','Version'),('events','Events','number'),('last_seen_ms','Last seen','time')])])]
COMMON=r'''
function present(raw){
 const data={title:SPEC.name,subtitle:SPEC.subtitle,scope:'Production · last 24 hours · deduplicated event IDs · verification probes excluded',generated_at:new Date().toISOString(),trace_enabled:true,raw,tables:SPEC.tables,cards:SPEC.cards.map(c=>({...c,value:raw[c.group]?.[0]?.[c.key]??null}))};
 if(SPEC.slug==='overview'){
  data.services=['backend','worker','web','daemon'].map(source=>({source,...(raw.sources?.find(r=>r.source===source)||{last_seen_ms:null})}));
  const start=Math.floor((Date.now()-86400000)/3600000)*3600000;
  const byHour=new Map((raw.trend||[]).map(r=>[Number(r.at_ms),Number(r.value)]));
  data.chart={title:'Event volume',note:'Hourly buckets · UTC · first and current hours are partial',points:Array.from({length:25},(_,i)=>({at_ms:start+i*3600000,value:byHour.get(start+i*3600000)||0}))};
 }
 const bytes=v=>{let n=0;for(const c of JSON.stringify(v)){const p=c.codePointAt(0);n+=p<128?1:p<2048?2:p<65536?3:4;}return n;};
 while(bytes(data)>60000){const largest=Object.values(raw).filter(r=>Array.isArray(r)&&r.length>5).sort((a,b)=>JSON.stringify(b).length-JSON.stringify(a).length)[0];if(!largest)throw new Error('Window state exceeds limit');largest.pop();data.rows_trimmed=true;}
 return data;
}
export default defineProcessor({
 init:async()=>{const raw={};for(const [key,sql] of Object.entries(SPEC.queries))raw[key]=await mission_control.query(sql);return present(raw);},
 subscriptions:Object.fromEntries(Object.entries(SPEC.queries).map(([key,sql])=>[key,{triggers:[{table:'siliconhook'}],sql,mode:'snapshot',onTrigger:(json,rows)=>present({...json.raw,[key]:rows})}])),
 tools:{summary:{args:{},run:json=>({title:json.title,scope:json.scope,generated_at:json.generated_at,cards:json.cards})},trace_request:{args:{request_id:'string'},run:async(json,{request_id})=>{if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(request_id))throw new Error('Enter a valid trace UUID');return {request_id,rows:await mission_control.query(TRACE_SQL+" WHERE request_id='"+request_id.toLowerCase()+"' ORDER BY at_ms ASC LIMIT 40")};}}}
});
'''
for v in VIEWS:
 folder=ROOT/v['slug'];folder.mkdir(exist_ok=True)
 (folder/'processor.js').write_text('// Generated by ../build.py; credentials are supplied by the runtime.\nconst SPEC='+json.dumps(v,indent=2)+';\nconst TRACE_SQL='+json.dumps(TRACE)+';\n'+COMMON)
(ROOT/'queries.json').write_text(json.dumps(VIEWS,indent=2)+'\n')
print('Generated four Hook Space Windows')
