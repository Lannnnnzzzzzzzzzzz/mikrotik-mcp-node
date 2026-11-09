# MikroTik MCP — JavaScript

Server MCP JavaScript/Node.js dengan implementasi orisinal untuk pengelolaan MikroTik RouterOS. Proyek ini memakai katalog path tetap, field allowlist dan arsitektur sendiri; bukan salinan penuh atau terjemahan baris-per-baris dari repositori referensi.

## Cakupan yang sudah diverifikasi

Handshake MCP mendaftarkan **312 tool**. Katalog memiliki **229 resource** pada **218 path RouterOS API unik**, dalam 8 kelompok: 56 hanya-baca dan 173 dengan field perubahan allowlist. Sebagai pembanding, repositori referensi mendokumentasikan 983 tool dalam 155 modul. Hitungan tersebut tidak langsung sebanding: banyak operasi pada proyek ini memakai pembaca atau planner generik, dan **fiturnya belum setara penuh** dengan referensi.

| Kelompok | Cakupan utama |
| --- | --- |
| System | Identitas, paket/update, jam, resource/sensor, user/group, scheduler RouterOS, script/log, sertifikat, watchdog, SSH, berkas, RouterBOARD dan maintenance terpilih. |
| Interfaces | Ethernet, bridge/port/VLAN, bonding, switch chip dan port isolation, PoE, interface list, Wi-Fi lama/baru, CAPsMAN, MAC server dan RoMON. |
| VPN | WireGuard, PPP dan beberapa client, IPsec, OpenVPN/SSTP/L2TP, VXLAN, RADIUS dan User Manager. |
| Routing | IPv4/IPv6, routing table/rule, BGP, OSPF, RIP, BFD, RPKI, VRF, IGMP/PIM dan next-hop; simulasi kandidat route IPv4/IPv6 terbatas. |
| Firewall | Filter/NAT/mangle/raw, address list, koneksi terlacak, IPv6 firewall dan audit konservatif potensi shadowing filter. |
| Services | DHCPv4/v6, relay/pool/lease, audit integritas DHCP, DNS/resolver beserta auditnya, Hotspot, UPnP, web proxy dan SOCKS. |
| QoS | Simple queue, queue tree/type/interface, Traffic Flow, graphing dan bandwidth-server. |
| Monitoring | Ping/traceroute, trafik/interface stats, neighbor/Netwatch, capability probe, kesehatan router, audit WAN/VLAN/WireGuard/routing BGP-OSPF-RIP-BFD, profil keamanan wireless, risiko scheduler/skrip, inventaris klien wireless, TZSP/PCAP lokal dan ringkasan statistik capture privat. |

Workflow khusus mencakup rencana port-forward, scaffolding VLAN IPv4 dan preview VLAN IPv6 dengan pemeriksaan konflik dasar, preview mesh WireGuard dengan pemeriksaan baseline, audit link WireGuard dua arah yang dideklarasikan pengguna, simulasi kandidat route IPv4/IPv6, audit urutan filter firewall, audit integritas DHCP dan DNS, audit profil keamanan wireless, pemeriksaan statis risiko scheduler/skrip, audit status protokol routing, inventaris klien wireless lintas driver, receiver TZSP/PCAP lokal, capture sniffer terkelola maksimal 60 detik dengan cleanup best-effort, inventaris snapshot/diff, dashboard loopback baca-saja, ringkasan AAA, bundle dukungan privat berbasis resource allowlist, alert lokal dengan polling dan webhook transisi opsional, serta create/download/upload/list/delete terbatas untuk backup biner terenkripsi termasuk penelusuran versi S3 dan penghapusan satu versi terpilih.

## Backup terenkripsi dan SFTP

`create_encrypted_router_backup` membuat file `.backup` terenkripsi di router, dengan frasa sandi minimal 16 karakter yang hanya dipakai pada pemanggilan tersebut. Tool tidak menyimpan atau mengembalikan frasa sandi. `download_encrypted_router_backup` mengunduh file melalui SSH/SFTP **hanya jika fingerprint kunci host cocok** dengan pin yang dikonfigurasi, membatasi transfer sampai 100 MiB, menyimpan file lokal dengan permission `0600`, lalu mencatat ukuran dan SHA-256. Direktori vault dibuat privat (`0700`). Salinan di router tetap ada.

Restore belum tersedia. Dokumentasi RouterOS menunjukkan `/system/backup/load` meminta jawaban terminal interaktif “Restore and reboot? [y/N]”; proyek native API ini belum memiliki sesi PTY/SSH persisten yang dapat menangani prompt itu dengan aman. Jangan menganggap upload file saja sebagai restore. Backup biner terikat perangkat/versi RouterOS dan tidak memuat database User Manager maupun The Dude. Lifecycle/retensi S3 dan ekspor database User Manager juga belum tersedia. Simpan frasa sandi secara terpisah dan gunakan penyimpanan lokal dengan full-disk encryption; permission privat bukan pengganti enkripsi disk.

Backup memerlukan RouterOS API TLS dengan pemeriksaan sertifikat tetap aktif, kredensial SSH terpisah dan fingerprint SHA-256 yang diverifikasi melalui sumber tepercaya. Jangan mempercayai hasil `ssh-keyscan` begitu saja—cocokkan fingerprint dengan konsol/admin RouterOS melalui kanal terpisah. Contoh environment satu router:

```text
MIKROTIK_SSH_PORT=22
MIKROTIK_SSH_USERNAME=backup-user
MIKROTIK_SSH_PASSWORD=<ambil dari secret store MCP host>
MIKROTIK_SSH_HOST_KEY_SHA256=SHA256:<fingerprint-yang-sudah-diverifikasi>
```

Untuk `MIKROTIK_ROUTERS_JSON`, setiap entri dapat memiliki `sshPort`, `sshUsername`, `sshPassword`, dan `sshHostKeyFingerprint`; environment di atas menjadi fallback global. Jangan masukkan kredensial nyata ke repository.

Operasi create/download membutuhkan `MIKROTIK_ALLOW_WRITES=true`, `MIKROTIK_ALLOW_HIGH_RISK_WRITES=true`, dan konfirmasi persis sesuai pesan tool, misalnya `CREATE ENCRYPTED BACKUP <deviceId> <name>`. Penghapusan salinan **lokal saja** juga meminta `MIKROTIK_ALLOW_DESTRUCTIVE_OPERATIONS=true` dan `DELETE LOCAL ENCRYPTED BACKUP <backupId>`. Menghapus salinan lokal tidak menghapus file di router.

### Upload, daftar, dan hapus salinan di S3

`upload_encrypted_router_backup_to_s3` hanya menerima backup yang sudah diunduh ke vault lokal. Tool mengalirkan file RouterOS yang sudah terenkripsi ke bucket S3 standar; object key diturunkan sendiri dari prefix, ID router dan UUID backup, bukan disediakan pemanggil. PutObject memakai `ExpectedBucketOwner`, SHA-256, `If-None-Match: *` (menolak overwrite), dan server-side encryption (`AES256` default atau `aws:kms`). Hanya region AWS normal yang didukung—tidak ada endpoint kustom.

Aktifkan `MIKROTIK_S3_ENABLED=true`, isi bucket, region dan ID akun pemilik bucket 12 digit; lihat [.env.example](.env.example). Kredensial dibaca melalui default credential chain AWS untuk Node.js, bukan disimpan oleh proyek. Gunakan bucket privat dan izin least-privilege; KMS memerlukan izin KMS yang sesuai. Pemilik tetap harus memilih dan menguji versioning, lifecycle/retensi dan kebijakan bucket. Upload memerlukan kedua gate write dan konfirmasi persis seperti yang diminta tool; tidak menghapus file lokal/router. Jika respons jaringan ambigu, periksa object key di akun S3 sebelum mencoba ulang.

`list_encrypted_router_backups_in_s3` hanya membaca satu halaman (maksimum 100 objek) pada prefix router yang dipilih, memerlukan `MIKROTIK_S3_ALLOW_LISTING=true` dan izin `s3:ListBucket` yang dibatasi pada prefix; body file tidak dibaca. `list_encrypted_router_backup_versions_in_s3` membaca satu halaman versi (maksimum 100) untuk key `.backup` UUID yang dibentuk server, memerlukan `s3:ListBucketVersions`, dan tidak membaca body maupun delete marker. `delete_encrypted_router_backup_from_s3` mengirim permintaan untuk satu key turunan saja; pada bucket berversi, ini biasanya membuat delete marker, bukan menghapus versi lama. `delete_encrypted_router_backup_version_from_s3` dapat mengirim permintaan penghapusan hanya untuk satu `versionId` yang dipilih pada key turunan itu. Penghapusan versi memerlukan `MIKROTIK_S3_ALLOW_DELETE=true`, `MIKROTIK_S3_ALLOW_VERSION_PURGE=true`, kedua gate write, gate destructive, serta konfirmasi penuh berisi bucket/key/version ID. Kedua operasi delete melaporkan permintaan diterima, bukan penghapusan permanen; Object Lock atau retensi dapat menghalangi. Pengelolaan lifecycle/retensi dan purge massal tetap tidak tersedia.

Semua fungsi S3 mati secara default. Listing objek dan versi tidak memerlukan gate write, tetapi perlu `MIKROTIK_S3_ALLOW_LISTING=true`; penghapusan satu key memerlukan `MIKROTIK_S3_ALLOW_DELETE=true`, sedangkan penghapusan satu versi juga perlu `MIKROTIK_S3_ALLOW_VERSION_PURGE=true`. Keduanya memerlukan `MIKROTIK_ALLOW_WRITES=true`, `MIKROTIK_ALLOW_HIGH_RISK_WRITES=true` dan `MIKROTIK_ALLOW_DESTRUCTIVE_OPERATIONS=true`.

## Analisis route, firewall, VLAN IPv6, dan capture

`simulate_ipv4_route_candidates` merangking route kandidat untuk satu alamat IPv4 dan satu routing table dari snapshot terbatas 500 route. Ia tidak mensimulasikan rekursi gateway, routing rules/VRF, forwarding atau keterjangkauan; bukti yang tak lengkap menghasilkan status tidak diketahui.

`simulate_ipv6_route_candidates` memberi peringkat kandidat untuk satu alamat IPv6 dan routing table dari snapshot hingga 500 route. Ia tidak mengevaluasi gateway, rule/VRF, forwarding atau keterjangkauan. Prefix, gateway dan alamat tujuan tidak dikembalikan; daftar tidak lengkap atau field tak dikenal menghasilkan status tidak diketahui.

`audit_firewall_rule_order` membaca semua properti aturan filter IPv4/IPv6 agar syarat yang tidak dikenal tidak dianggap cocok. Hanya temuan sintetis, alasan ketidakpastian dan hitungan coverage yang dikembalikan—bukan alamat, komentar atau nilai match. Batas respons API 8 MiB dan 5.000 aturan per keluarga berlaku; hasilnya bukan simulasi paket.

`preview_ipv6_vlan_segment` menolak benturan VLAN/prefix yang terdeteksi lalu menyiapkan rencana konfigurasi terbatas tanpa menerapkannya. Rencana tidak mencakup DHCPv6, router advertisement atau firewall IPv6. Kondisi router dapat berubah setelah preview; jalankan ulang sebelum apply.

## Audit DHCP, DNS, Wi-Fi, dan scheduler

`audit_dhcp_integrity` memeriksa referensi server/pool, range yang tumpang tindih, pool di luar network, serta lease statis yang berada di luar semua network DHCP yang tercakup lengkap. Reservasi statis di luar pool dinamis tetapi masih di dalam subnet dianggap sah. Audit hanya mengembalikan kode, jumlah, indeks, dan status cakupan—bukan alamat, nama, MAC, atau komentar. Format dinamis, izin kurang, dan snapshot parsial ditandai tidak pasti.

`audit_dns_resolver` memeriksa keberadaan resolver upstream, opsi remote request dan nama static DNS duplikat. `allow-remote-requests` hanya sinyal tinjauan; tanpa bukti firewall dan antarmuka, tool tidak menyimpulkan bahwa resolver terbuka ke Internet. Nama, alamat, URL DoH, dan komentar tidak ditampilkan.

`audit_wireless_security_profiles` meninjau profil wireless lama, CAPsMAN, dan WiFi baru untuk indikator eksplisit seperti tanpa autentikasi, WPA1, WEP/TKIP, perlindungan management-frame dan keberadaan secret. Secret dibaca hanya untuk mereduksinya menjadi boolean dan tidak pernah dikembalikan. Nama profil, SSID, kunci, komentar, MAC, serta baris mentah tidak masuk hasil; field yang hilang/versi yang tak dikenal menjadi tidak pasti.

`audit_scheduler_safety` memeriksa pola terbatas pada event scheduler dan source skrip, tanpa menjalankannya atau mengembalikan isi/perintah. Entry scheduler yang jelas dinonaktifkan diabaikan; status enable yang hilang ditandai tidak pasti. Ini pemeriksaan statis advisory: pola dapat melewatkan perilaku tidak langsung atau menghasilkan false positive, dan bukan pengganti peninjauan kode.

`summarize_tzsp_capture` membaca hanya file PCAP lokal yang selesai dan privat, lalu mengembalikan hitungan paket/protokol tanpa alamat IP/MAC, payload atau path file. Batasnya 64 MiB dan 100.000 paket.

## Ringkasan support yang menjaga privasi

`router_support_summary` mengumpulkan field sistem yang dipilih serta hitungan interface, alamat, route default, firewall, DHCP, WireGuard dan registrasi wireless. Output tidak memuat alamat IP/MAC, gateway, hostname klien, komentar, SSID, key atau record mentah; section yang tidak tersedia ditandai tidak diketahui dan hitungan terpotong ditandai parsial. Ini hanya snapshot hitungan, bukan export konfigurasi penuh.

`create_router_support_bundle` adalah mode terpisah dan opt-in (`MIKROTIK_SUPPORT_BUNDLE_ENABLED=true`): ia membaca katalog resource tetap, membatasi properti ke allowlist, menyunting field sensitif, membatasi ukuran, lalu membuat gzip JSON lokal dengan permission `0600`. File dapat tetap memuat IP privat, nama akun, topologi, komentar/label non-sensitif dan detail konfigurasi; konfirmasi eksplisit diperlukan. Ini bukan backup yang dapat dipulihkan, full CLI export, atau supout. File berada di `.data/support-bundles` (atau `<MIKROTIK_DATA_DIR>/support-bundles`) dan tidak dihapus otomatis.

## AAA, alert dan diagnostik

`router_aaa_overview` merangkum konfigurasi RADIUS/User Manager dan sesi yang tersedia saat itu. Field kredensial/shared-secret disaring. Sesi dapat terlambat atau tidak lengkap; ringkasan ini bukan laporan billing dan bukan dashboard historis.

Alert lokal mendukung ambang CPU, memori dan jumlah default route IPv4, evaluasi manual, histori perubahan status, serta polling periodik dalam proses. Polling **mati secara default**; aktifkan `MIKROTIK_ALERT_SERVICE_ENABLED=true`, lalu panggil `start_router_alert_service`. Jika juga mengaktifkan `MIKROTIK_ALERT_SERVICE_AUTOSTART=true`, polling otomatis dimulai saat proses MCP berikutnya berjalan, memakai aturan lokal yang tersimpan. Interval dibatasi 60 detik sampai 24 jam. Poller berhenti selama proses MCP tidak berjalan; opsi autostart bukan layanan OS atau scheduler eksternal. Webhook HTTPS transisi-only tersedia secara opsional melalui `MIKROTIK_ALERT_WEBHOOK_ENABLED=true` dan URL rahasia di `MIKROTIK_ALERT_WEBHOOK_URL`; URL tidak dikembalikan dan payload hanya berisi device ID, metrik, nilai, ambang dan status. Pengiriman memakai timeout 5 detik, tidak mengikuti redirect, dan tidak mencakup mute/cooldown atau eskalasi.

`run_speed_test` mewajibkan kredensial server bandwidth-test jarak jauh. Lima fase berdurasi minimum 5 detik (sekitar 30 detik total) dapat memenuhi kapasitas link dan membebani CPU kedua router; device-mode, firewall, izin dan bandwidth-server harus sudah benar. Bandwidth test, IP scan, flood-ping dan Wake-on-LAN memerlukan gate diagnostik aktif tambahan dan konfirmasi target.

## Penerima TZSP dan file PCAP lokal

Tool capture membuka penerima UDP lokal, menulis frame Ethernet TZSP v1 ke file classic PCAP privat, melihat metadata dan statistik paket/protokol tanpa alamat, serta menghapus file capture lokal setelah konfirmasi. Receiver mati secara default. Untuk mengaktifkannya, isi `MIKROTIK_TZSP_RECEIVER_ENABLED=true`, alamat IP lokal non-wildcard yang dapat dicapai router di `MIKROTIK_TZSP_BIND_ADDRESS`, port UDP (default `37008`), serta `MIKROTIK_TZSP_ALLOWED_SOURCES` berisi IP pengirim persis dipisahkan koma. Receiver manual dibatasi maksimal 600 detik, 64 MiB dan 100.000 frame. Semua capture memerlukan kedua gate write, gate active-diagnostics dan frasa konfirmasi tepat; penghapusan file juga perlu gate destructive.

`start_tzsp_capture_receiver` hanya membuka receiver lokal dan tidak mengubah RouterOS. Setelah receiver berjalan, setel dan mulai sniffer secara manual; `filter-stream=yes` disarankan. Contoh perintah yang dikembalikan tool (tidak dijalankan otomatis):

```text
/tool/sniffer/set streaming-enabled=yes streaming-server=<bind-address> streaming-port=37008 filter-stream=yes
/tool/sniffer/start
```

`capture_router_sniffer` mengotomatiskan receiver dan sniffer dalam satu panggilan maksimal 60 detik, menolak sniffer yang sudah aktif, lalu mencoba menghentikan sniffer serta memulihkan pengaturan streaming sebelumnya. Tool ini **mati secara default** (`MIKROTIK_TZSP_AUTOMATION_ENABLED=false`), dan memerlukan kedua gate write, gate active-diagnostics, receiver aktif, allowlist yang memuat IP router persis, serta konfirmasi. Cleanup best-effort; jika proses MCP, jaringan atau router berhenti saat capture, verifikasi `/tool/sniffer` secara manual sebelum mencoba lagi. TZSP UDP tidak terenkripsi atau terautentikasi; gunakan jaringan tepercaya dan allowlist IP. PCAP dapat berisi isi trafik privat. File tersimpan di `.data/captures` (atau `<MIKROTIK_DATA_DIR>/captures`) dan tidak otomatis dihapus. Sniffer tidak menjamin semua trafik tertangkap—misalnya frame yang diproses dengan hardware offload dapat tak terlihat. Mirror mangle per-flow, decoder live, dan panel dashboard belum tersedia.

## Yang belum setara dengan referensi

Safe Mode interaktif dan rollback otomatis belum tersedia; transaksi API berurutan bukan ACID. Restore backup belum tersedia karena [dokumentasi resmi RouterOS](https://help.mikrotik.com/docs/spaces/ROS/pages/40992852/Backup) meminta persetujuan terminal interaktif untuk reboot setelah load; proyek ini belum memiliki sesi PTY persisten. Lifecycle/retensi S3, ekspor database User Manager, full config export, supout, scheduler eksternal/telemetri alert persisten, otomatisasi sniffer/mirror yang tahan proses gagal, decoding live, traffic generator, CPU profiler, dashboard AAA historis, serta workflow lengkap beberapa fitur routing/VPN/wireless juga belum tersedia. Route simulation, audit urutan firewall, preview VLAN IPv6 dan bundle dukungan berbasis katalog tetap terbatas dan tidak membuktikan forwarding atau isolasi end-to-end. Beberapa operasi hanya disediakan sebagai pembaca resource atau planner generik. Lihat [FEATURE_PARITY.md](FEATURE_PARITY.md) untuk matriks yang lebih rinci dan sumber.

Snapshot merupakan inventaris konfigurasi terpilih, bukan backup yang dapat dipulihkan. Pembacaan internal memakai field allowlist yang membuang properti sensitif termasuk WireGuard preshared key; bila RouterOS mengembalikan field tambahan, hasilnya juga disaring. Native API commands diserialkan per koneksi agar jawaban berurutan tidak tertukar ketika beberapa pembacaan diminta bersamaan. Tool tidak menyediakan command string RouterOS bebas.

## Instalasi dan konfigurasi

Persyaratan: Node.js 20+ dan RouterOS dengan native API aktif. Utamakan API-SSL/TLS TCP 8729 dengan sertifikat tervalidasi; API biasa TCP 8728 mengirim kredensial tanpa enkripsi di jaringan.

```sh
npm install
npm test
npm start
```

Server menggunakan stdio; log operasional ditulis ke stderr. MCP host menyediakan environment dan secret store—server **tidak** memuat `.env`. Lihat [.env.example](.env.example). Contoh minimum satu router:

```text
MIKROTIK_HOST=192.0.2.1
MIKROTIK_USERNAME=mcp-readonly
MIKROTIK_PASSWORD=<ambil dari secret store MCP host>
MIKROTIK_TLS=true
MIKROTIK_PORT=8729
MIKROTIK_TLS_REJECT_UNAUTHORIZED=true
MIKROTIK_ALLOW_WRITES=false
MIKROTIK_ALLOW_HIGH_RISK_WRITES=false
MIKROTIK_ALLOW_ACTIVE_DIAGNOSTICS=false
MIKROTIK_ALLOW_DESTRUCTIVE_OPERATIONS=false
```

Banyak router dikonfigurasi dengan `MIKROTIK_ROUTERS_JSON`, berupa array atau objek `{ "defaultDevice": "...", "routers": [...] }`. Setiap entri memiliki `id`, `host` atau `hosts` (maksimal 8 endpoint untuk router yang sama), `username`, `password`, `tls`, dan `port`. Failover API hanya terjadi saat koneksi; operasi tidak diputar ulang setelah sesi tersambung. Field SSH/SFTP terpisah dan bersifat opsional kecuali tool backup dipakai.

Dashboard opsional memakai `MIKROTIK_DASHBOARD_ENABLED=true`. Dashboard hanya bind ke loopback (default `127.0.0.1:9090`) dan menolak Host header yang tidak tepercaya.

## Menjalankan dari OpenCode

Proyek ini menyertakan [`opencode.json`](opencode.json) yang mendaftarkan server MCP lokal melalui stdio, serta [`AGENTS.md`](AGENTS.md) berisi panduan agar OpenCode mengutamakan pembacaan dan menjaga operasi router tetap konservatif. Pastikan Node.js 20+ tersedia, jalankan `npm install` di direktori proyek, lalu mulai OpenCode dari direktori tersebut:

```sh
npm install
opencode
```

Di OpenCode, buka `/mcps` dan pastikan `mikrotik-mcp-js` berstatus connected; dari terminal, `opencode mcp list` juga dapat memeriksa koneksi. Untuk uji tanpa router, minta OpenCode menampilkan kemampuan keselamatan MCP (`router_safety_capabilities`) atau gunakan `npm test`. MCP akan mulai tanpa menghubungi router. Tool yang memerlukan router baru dapat dipakai setelah environment router disediakan.

Konfigurasi proyek memaksa gate perubahan, diagnostik aktif, operasi destruktif, bundle dukungan, polling/webhook alert, TZSP, S3, dan dashboard tetap mati. Ia juga sengaja mengosongkan `MIKROTIK_ROUTERS_JSON`, `MIKROTIK_HOST`, `MIKROTIK_USERNAME`, dan `MIKROTIK_PASSWORD`, jadi environment router warisan tidak bisa membuat MCP tersambung tanpa sengaja. Jangan menyimpan kata sandi RouterOS/SSH, URL webhook, atau kredensial AWS di file proyek. Untuk menghubungkan router lab milik sendiri, ubah entri terkait di `opencode.json` agar memakai referensi environment terlindungi, misalnya `"{env:MIKROTIK_HOST}"`; untuk beberapa router, gunakan `"{env:MIKROTIK_ROUTERS_JSON}"`. Gunakan akun least-privilege dan TLS terverifikasi. Jangan membuka gate keselamatan hanya demi membuat tool berjalan.

Jika perlu memetakan environment rahasia secara eksplisit di objek `environment` OpenCode, gunakan referensi environment (bukan nilainya):

```json
"MIKROTIK_HOST": "{env:MIKROTIK_HOST}",
"MIKROTIK_USERNAME": "{env:MIKROTIK_USERNAME}",
"MIKROTIK_PASSWORD": "{env:MIKROTIK_PASSWORD}"
```

Untuk konfigurasi banyak router, ganti nilai kosong `MIKROTIK_ROUTERS_JSON` di `opencode.json` dengan `"{env:MIKROTIK_ROUTERS_JSON}"` dan simpan JSON beserta kredensialnya di secret store, bukan di file proyek.

Lihat [konfigurasi MCP OpenCode](https://opencode.ai/docs/mcp-servers/) dan [konfigurasi proyek OpenCode](https://opencode.ai/docs/config/) untuk rincian resmi.

## Model keselamatan perubahan

Perubahan konfigurasi umum melewati `plan_router_change` atau `plan_router_transaction`, lalu tool apply dengan frasa tepat `APPLY <planId>` dan **kedua** gate write. Rencana satu kali pakai berlaku 10 menit. Transaksi berurutan bukan ACID; jika operasi gagal atau koneksi putus, kondisi parsial/tidak pasti mungkin terjadi. Tidak ada rollback otomatis yang dijanjikan.

Reboot, shutdown, install update, dan upgrade RouterBOARD memerlukan `MIKROTIK_ALLOW_DESTRUCTIVE_OPERATIONS=true` tambahan. Tool backup juga memakai konfirmasi khusus; pembuatan backup menolak API tanpa TLS tervalidasi. Bundle dukungan, webhook, dan automation sniffer memiliki flag opt-in terpisah yang default mati; capture sniffer juga memerlukan active-diagnostics gate. Semua gate tertutup dalam [.env.example](.env.example). Gate bukan pengganti permission RouterOS minimum, prosedur pemulihan dan peninjauan manusia.

## Data lokal dan pengujian

Snapshot, histori alert, backup terenkripsi, bundle dukungan dan capture PCAP tersimpan di `.data` (atau `MIKROTIK_DATA_DIR`); subfolder khususnya bernama `captures` dan `support-bundles`. Isi metadata backup tidak menyimpan passphrase maupun password API/SSH. Lindungi dan atur retensi direktori tersebut. Snapshot dan alert lama yang dibuat sebelum perubahan redaksi tidak otomatis dibersihkan.

`npm test` menjalankan **181 tes** unit/integrasi dan semuanya lulus. Cakupannya termasuk peer API tiruan, safety gates, redaksi, backup vault privat, SFTP upload/download dengan host-key pin dan checksum, bundle gzip privat, webhook alert minimisasi payload, workflow sniffer dengan mock cleanup, TZSP/PCAP, S3 versi objek, audit firewall, simulasi route IPv4/IPv6, audit DHCP/DNS/profil Wi-Fi/scheduler, preview VLAN IPv6 dan pemulihan polling alert melalui autostart opt-in. Handshake MCP stdio aktual mengonfirmasi **312 tool** terdaftar. Tidak ada pengujian live pada router; jumlah ini tidak membuktikan kesetaraan fitur dengan repositori referensi.

## Referensi

- [Dokumentasi RouterOS API](https://help.mikrotik.com/docs/spaces/ROS/pages/47579160/RouterOS+API)
- [RouterOS Backup](https://help.mikrotik.com/docs/spaces/ROS/pages/40992852/Backup)
- [RouterOS SSH](https://help.mikrotik.com/docs/spaces/ROS/pages/132350014/SSH)
- [RouterOS Packet Sniffer](https://help.mikrotik.com/docs/spaces/ROS/pages/8323088/Packet+Sniffer)
- [Wireshark TZSP dissector](https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-tzsp.c)
- [Classic PCAP file format](https://wiki.wireshark.org/Development/LibpcapFileFormat)
- [Amazon S3 PutObject API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html)
- [S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
- [AWS SDK for JavaScript v3 Node.js credentials](https://docs.aws.amazon.com/sdk-for-javascript/v3/developer-guide/setting-credentials-node.html)
- [SSH2 SFTP API](https://github.com/mscdex/ssh2/blob/master/SFTP.md)
- [Repositori referensi mikrotik-mcp](https://github.com/mikrotik-mcp/mikrotik-mcp)
