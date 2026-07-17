#!/bin/bash
# One-shot live FLIR test: capture a 36-frame IR strobe burst, score lit frames.
# Usage: bash live-flir-test.sh <name> [ir-device]    (e.g. genuine-car, phone-ir)
[ -n "$1" ] || { echo "usage: bash live-flir-test.sh <name>"; exit 1; }
d=~/irlume-suncal/flir-candidate/live-"$1"-$(date +%H%M%S); mkdir -p "$d"
export ORT_DYLIB_PATH=/usr/share/irlume/onnxruntime/lib/libonnxruntime.so
M=/usr/share/irlume/models
echo "IR burst (~2.5s) into $d in 3..."; sleep 3
~/irlume/target/release/examples/landmark_dump \
  "$M/face_detection_yunet_2023mar.onnx" "$M/face_landmark.onnx" "$d" "${2:-/dev/video2}" 36 \
  || { echo "capture failed (camera busy? retry in a few seconds)"; exit 1; }
~/hf-venv/bin/python - "$d" <<'PYEOF'
import sys
from pathlib import Path
import numpy as np, cv2, onnxruntime as ort
HOME = Path.home()
YUNET = str(HOME/"irlume/models/face_detection_yunet_2023mar.onnx")
sess = ort.InferenceSession(str(HOME/"irlume-suncal/flir-candidate/flir-model.onnx"),
                            providers=["CPUExecutionProvider"])
inp = sess.get_inputs()[0].name
def align(img, bb, pad=16, fill=127):
    b=[int(v) for v in bb]
    x1=b[0]-int((b[2]-b[0]+1)*pad/112); x2=b[2]+int((b[2]-b[0]+1)*pad/112)
    y1=b[1]-int((b[3]-b[1]+1)*pad/112); y2=b[3]+int((b[3]-b[1]+1)*pad/112)
    b=[max(0,x1),max(0,y1),min(img.shape[1]-1,x2),min(img.shape[0]-1,y2)]
    ph,pw=b[3]-b[1]+1,b[2]-b[0]+1
    if pw>ph:
        off=(pw-ph)//2; b[1]=max(0,b[1]-off); b[3]=min(img.shape[0]-1,b[1]+pw-1); ds=pw
    else:
        off=(ph-pw)//2; b[0]=max(0,b[0]-off); b[2]=min(img.shape[1]-1,b[0]+ph-1); ds=ph
    dst=np.full((ds,ds,3),fill,np.uint8)
    yo=(ds-(b[3]-b[1]+1))//2; xo=(ds-(b[2]-b[0]+1))//2
    dst[yo:yo+b[3]+1-b[1], xo:xo+b[2]+1-b[0]]=img[b[1]:b[3]+1,b[0]:b[2]+1]
    return cv2.resize(dst,(128,128))
vals, dark, nodet = [], 0, 0
for p in sorted(Path(sys.argv[1]).glob("*.pgm")):
    g = cv2.imread(str(p), cv2.IMREAD_GRAYSCALE)
    if g is None: continue
    amb = g.mean()
    if amb < 10: dark += 1; continue
    g3 = cv2.cvtColor(g, cv2.COLOR_GRAY2BGR)
    h,w = g3.shape[:2]
    det = cv2.FaceDetectorYN.create(YUNET,"",(w,h),0.5,0.3,5000)
    _,faces = det.detect(g3)
    if faces is None or len(faces)==0:
        nodet += 1; print(f"{p.name}: amb={amb:.0f} no face in IR"); continue
    f = max(faces,key=lambda f:f[2]*f[3]); x,y,bw,bh=f[:4]
    crop = align(g3,[x,y,x+bw,y+bh])[8:120,8:120].astype(np.float32)
    t = ((crop-127.5)*0.0078125).transpose(2,0,1)[np.newaxis]
    o = sess.run(None,{inp:t})[0][0]
    e = np.exp(o-o.max()); pf = float((e/e.sum())[0])
    vals.append(pf)
    print(f"{p.name}: amb={amb:.0f} p_fake = {pf:.4f}  {'FAKE' if pf>=0.5 else 'live'}")
print(f"\ndark-phase skipped: {dark}, no-face: {nodet}")
if vals:
    a=np.array(vals)
    print(f"summary: n={len(a)} median={np.median(a):.4f} flagged@0.5 = {(a>=0.5).sum()}/{len(a)}")
PYEOF
