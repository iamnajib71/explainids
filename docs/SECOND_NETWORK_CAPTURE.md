# Capturing the second network (one or two evenings at home)

For the team member whose home network is the second study network. The plan is fixed in
[`PREREGISTRATION_NET2.md`](PREREGISTRATION_NET2.md); follow it exactly.

## Before the first capture

1. **Ask everyone in the household**, in plain words: "For a university project I'd like to record the network
   traffic of our home WiFi from my own PC for about three hours this evening (and another evening). Nothing is
   sent anywhere; only statistics about connections are kept and the recordings are deleted after processing.
   Is that OK?" Capture only if everyone agrees. Note the date you asked.
2. **Install Wireshark** on your Windows PC from https://www.wireshark.org/download.html, and tick *Install Npcap*
   during setup.
3. Copy `scripts/capture_pcap_blocks.ps1` from the repository to the PC.

## Each evening

1. Use the household normally: no test traffic, no speed tests, nothing staged.
2. Find your WiFi interface number:
   ```powershell
   & "C:\Program Files\Wireshark\dumpcap.exe" -D
   ```
3. Start the capture with an **empty folder per evening**, then leave the PC on and awake for about 2 h 45 min:
   ```powershell
   powershell -ExecutionPolicy Bypass -File capture_pcap_blocks.ps1 -Interface <number> -Out D:\net2_evening1
   ```
   Use `D:\net2_evening2` on the second evening (a later day).

## Afterwards

- Bring the folders to the analysis PC **in person on a USB drive**. Do not email, upload or cloud-sync them: they
  contain the household's raw traffic.
- On the analysis PC (repository root):
  ```powershell
  python scripts/import_pcap_blocks.py D:\net2_evening1 --converter-argv '<converter json from LOCAL_SENSOR.md>' --study data/sensor/study_net2_evening1.json --discard-pcap
  ```
  `--discard-pcap` deletes each raw capture once its flows validate. Then delete the folders from the USB drive.
- Then run the pre-registered analysis (`PREREGISTRATION_NET2.md`, "Analysis").

If only one evening is possible, capture it as above; the pre-registration's one-evening fallback applies.
