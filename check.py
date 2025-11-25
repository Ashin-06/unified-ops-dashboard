#!/usr/bin/env python3
"""
Quick diagnostic script to check database state
RUN THIS ON THE MASTER SERVER TO DEBUG ISSUES
"""
import sqlite3
import json
from pathlib import Path
import os

# Auto-detect database path
if os.name == 'nt':
    DB_PATH = Path("C:/ProgramData/ServerMonitor/Data/monitor.db")
else:
    DB_PATH = Path("/opt/server_monitor/Data/monitor.db")

def check_db():
    global DB_PATH   # <-- FIXED: moved to top

    print("=" * 80)
    print("DATABASE DIAGNOSTIC CHECK")
    print("=" * 80)
    
    if not DB_PATH.exists():
        print(f"❌ Database not found at: {DB_PATH}")
        print("\nTrying alternate paths...")
        alternates = [
            Path("./monitor.db"),
            Path("./Data/monitor.db"),
            Path("../Data/monitor.db"),
        ]
        for alt in alternates:
            if alt.exists():
                print(f"✅ Found database at: {alt.absolute()}")
                DB_PATH = alt     # now allowed
                break
        else:
            print("❌ Could not find database in any common location")
            return
    else:
        print(f"✅ Database found at: {DB_PATH}")
    
    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()
    
    # 1. Check table structure
    print("\n📋 Table Structure (system_metrics):")
    cur.execute("PRAGMA table_info(system_metrics)")
    columns = cur.fetchall()
    
    critical_columns = ['disk_usage', 'uptime', 'total_connections']
    found_columns = [col[1] for col in columns]
    
    for col in columns:
        col_name = col[1]
        col_type = col[2]
        marker = "✅" if col_name in critical_columns else "  "
        print(f"   {marker} {col_name} ({col_type})")
    
    # Check if critical columns exist
    print("\n🔍 Critical Columns Check:")
    for ccol in critical_columns:
        if ccol in found_columns:
            print(f"   ✅ {ccol} - EXISTS")
        else:
            print(f"   ❌ {ccol} - MISSING (DATABASE NEEDS MIGRATION)")
    
    # 2. Check recent data
    print("\n📊 Recent Data (Last 5 rows):")
    try:
        cur.execute("""
            SELECT timestamp, hostname, cpu_percent, memory_percent, 
                   disk_usage, uptime, total_connections 
            FROM system_metrics 
            ORDER BY timestamp DESC 
            LIMIT 5
        """)
        rows = cur.fetchall()
        
        if not rows:
            print("   ❌ No data found!")
        else:
            for i, row in enumerate(rows, 1):
                ts, host, cpu, mem, disk, uptime, conns = row
                print(f"\n   Row {i}:")
                print(f"      Timestamp: {ts}")
                print(f"      Hostname: {host}")
                print(f"      CPU: {cpu}%")
                print(f"      Memory: {mem}%")
                
                if disk is None or disk == 0.0:
                    print(f"      Disk: {disk if disk is not None else 'NULL'}% ⚠️ SHOULD NOT BE ZERO")
                else:
                    print(f"      Disk: {disk}% ✅")
                
                if uptime is None or uptime == 0:
                    print(f"      Uptime: {uptime if uptime is not None else 'NULL'}s ⚠️ SHOULD NOT BE ZERO")
                else:
                    print(f"      Uptime: {uptime}s ✅")
                
                if conns is None or conns == 0:
                    print(f"      Connections: {conns if conns is not None else 'NULL'} ⚠️ MIGHT BE ZERO")
                else:
                    print(f"      Connections: {conns} ✅")
    except Exception as e:
        print(f"   ❌ Error reading data: {e}")
    
    # 3. Check distinct hostnames
    print("\n🖥️  Distinct Hostnames:")
    cur.execute("SELECT DISTINCT hostname FROM system_metrics")
    hosts = cur.fetchall()
    
    if not hosts:
        print("   ❌ No hostnames found in database")
    else:
        for host in hosts:
            print(f"\n   📡 {host[0]}")
            try:
                cur.execute("""
                    SELECT cpu_percent, memory_percent, disk_usage, uptime, total_connections, timestamp
                    FROM system_metrics 
                    WHERE hostname = ?
                    ORDER BY timestamp DESC 
                    LIMIT 1
                """, (host[0],))
                latest = cur.fetchone()
                if latest:
                    cpu, mem, disk, uptime, conns, ts = latest
                    print(f"      Latest: CPU={cpu}%, Mem={mem}%, Disk={disk}, Uptime={uptime}, Conns={conns}")
                    print(f"      Time: {ts}")
                    
                    if disk == 0 or disk is None:
                        print(f"      ⚠️  WARNING: Disk is {disk} - Agent not sending data?")
                    if uptime == 0 or uptime is None:
                        print(f"      ⚠️  WARNING: Uptime is {uptime} - Agent not sending data?")
            except Exception as e:
                print(f"      ❌ Error: {e}")
    
    # 4. Check alerts
    print("\n⚠️  Recent Alerts:")
    cur.execute("SELECT COUNT(*), hostname FROM alerts GROUP BY hostname")
    alert_counts = cur.fetchall()
    if not alert_counts:
        print("   ✅ No alerts")
    else:
        for count, host in alert_counts:
            print(f"   - {host}: {count} alerts")
    
    # 5. Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    has_critical_columns = all(ccol in found_columns for ccol in critical_columns)
    has_data = bool(rows) if 'rows' in locals() else False
    
    if not has_critical_columns:
        print("❌ CRITICAL: Missing database columns!")
        print("   FIX: Restart main.py to run migrations")
    elif not has_data:
        print("⚠️  WARNING: Database has columns but no data")
        print("   FIX: Check if agents are running and sending data")
    else:
        has_zeros = False
        if rows:
            for row in rows:
                disk, uptime, conns = row[4], row[5], row[6]
                if (disk is None or disk == 0) or (uptime is None or uptime == 0):
                    has_zeros = True
                    break
        
        if has_zeros:
            print("⚠️  WARNING: Data exists but contains zeros")
            print("   FIX: Agents not calculating/sending extended stats")
            print("   ACTION: Update agent.py on all remote servers")
        else:
            print("✅ SUCCESS: Everything looks good!")
            print("   Database has correct structure and valid data")
    
    conn.close()

if __name__ == "__main__":
    check_db()
