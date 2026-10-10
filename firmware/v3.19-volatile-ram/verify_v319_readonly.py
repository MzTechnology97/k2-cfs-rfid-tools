#!/usr/bin/env python3
"""Run only AFTER flashing v3.19. Query firmware through Moonraker; NO SET."""
import urllib.request,json,sys
from pathlib import Path
BASE='http://127.0.0.1:7125'

def req(path,data=None):
 opts={} if data is None else {'data':json.dumps(data).encode(),'headers':{'Content-Type':'application/json'},'method':'POST'}
 with urllib.request.urlopen(urllib.request.Request(BASE+path,**opts),timeout=12) as r:return json.load(r)

before=req('/printer/objects/query?webhooks&print_stats')['result']['status']
assert before['webhooks']['state']=='ready' and before['print_stats']['state']=='standby','PRINTER NOT IDLE: no diagnostic request sent'
print('READ ONLY: querying 28 parameters through BOX_CFS_CONFIG_INFO')
req('/printer/gcode/script',{'script':'BOX_CFS_CONFIG_INFO'})
r=req('/printer/objects/query?webhooks&print_stats&box_cfs_runtime')['result']['status']
cfs=r['box_cfs_runtime'];values=cfs.get('values',{})
expected={
'feeder_forward_speed':255,'hub_forward_speed':100,'hub_transition_speed':200,'hub_insert_speed':155,
'feeder_reverse_speed':255,'hub_reverse_speed':80,'reverse_detooth_enable':0,
'hub_transition_wait_ms':3200,'insert_sensor_timeout_ms':700,'hub_pullback_timeout_ms':5000,
'unload_sensor_timeout_ms':1000,'rfid_seek_speed':160,'rfid_measure_speed':120,
'rfid_reposition_speed':100,'rfid_seek_move_ms':800,'rfid_seek_settle_ms':200,
'rfid_post_auth_wait_ms':1000,'rfid_pre_measure_settle_ms':10,
'rfid_neighbor_detect_delay_ms':400,'rfid_neighbor_settle_ms':100,
'feed_total_timeout_20ms_ticks':1250,'feed_recovery_timeout_ms':3000,
'odometer_stall_20ms_ticks':25,'rfid_neighbor_retry_count':3,
'reverse_detooth_timeout_ms':1000,'buffer_fill_timeout_ms':30000,
'transition_detect_timeout_ms':300,'load_retry_count':3}
wrong={k:{'expected':v,'observed':values.get(k)} for k,v in expected.items() if values.get(k)!=v}
checks={'printer_ready':r['webhooks']['state']=='ready','no_printing':r['print_stats']['state']=='standby',
'api_v2':cfs.get('protocol_version')==2,'feature_signature_F7':cfs.get('firmware_features')==0xF7,
'catalog_28':cfs.get('parameter_count')==28,'all_28_default_values':not wrong,'no_error':cfs.get('last_error') is None}
report={'passed':all(checks.values()),'checks':checks,'unexpected':wrong,'status':cfs,'writes_performed':False,
'warning':'A PASS verifies ROM defaults and API only; NOT RAM SET/RESET reliability or heap behavior under load.'}
path=Path(__file__).with_name('V319_FIRST_BOOT_READBACK.json');path.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'pass':report['passed'],'checks':checks,'unexpected':wrong,'saved':str(path)},indent=2))
sys.exit(0 if report['passed'] else 2)
