from sqlalchemy import create_engine, text

engine = create_engine('postgresql+psycopg://railsentinel:railsentinel@localhost:5432/railsentinel')
patrol_id = '00000000-0000-4000-8000-000000000004'

sql = text("""
INSERT INTO devices (id, station_id, device_uid, device_type, status, label) 
VALUES (:id, :sid, 'patrol-sim-01', 'rover', 'active', 'Mobile Patrol Simulator') 
ON CONFLICT DO NOTHING
""")

with engine.begin() as conn:
    conn.execute(sql, {'id': patrol_id, 'sid': '00000000-0000-4000-8000-000000000001'})
    
print('Patrol device registered:', patrol_id)
