from sqlalchemy import create_engine, text

engine = create_engine('postgresql+psycopg://railsentinel:railsentinel@localhost:5432/railsentinel')
cctv_id = '00000000-0000-4000-8000-000000000005'
station_id = '00000000-0000-4000-8000-000000000001'

sql = text("""
INSERT INTO devices (id, station_id, device_uid, device_type, status, label) 
VALUES (:id, :sid, 'cctv-webcam-01', 'cctv_ingest', 'active', 'Station Gate 1 - Laptop CCTV') 
ON CONFLICT (device_uid) DO UPDATE 
SET status = 'active', label = 'Station Gate 1 - Laptop CCTV'
""")

with engine.begin() as conn:
    conn.execute(sql, {'id': cctv_id, 'sid': station_id})
    
print('CCTV device registered successfully:', cctv_id)
