//! `lumend` — the privileged daemon. The ONLY component that touches the camera,
//! IR emitter, ONNX models, templates and TPM. Untrusted clients (pam_lumen, the
//! CLI) connect over a Unix socket; raw frames never leave this process. This is
//! the Linux analogue of Windows Hello ESS's isolated camera->matcher pathway.
//!
//! Trust boundary: authenticate every peer with SO_PEERCRED before honouring
//! privileged requests (enroll/delete). D-Bus is deliberately NOT used — an
//! explicit peer-credential check on our own socket is the stronger boundary
//! (this is the concrete hardening over the `visage` reference design).

use lumen_common::{Request, Response, SOCKET_PATH};

fn main() {
    eprintln!("lumend (placeholder) — would listen on {SOCKET_PATH}");
    // TODO:
    //  1. Load models once: YuNet detector + AuraFace embedder (lumen-vision).
    //  2. Open + trust-bind cameras (lumen-camera).
    //  3. Bind Unix socket root:lumen 0660; for each conn: read SO_PEERCRED.
    //  4. Dispatch Request -> handle_* ; enforce authz on privileged ops.
}

/// Peer identity from SO_PEERCRED — the basis for authorization.
struct Peer {
    uid: u32,
    #[allow(dead_code)]
    gid: u32,
    #[allow(dead_code)]
    pid: i32,
}

/// Authorize a privileged request: only root, or the target user themselves,
/// may enroll/delete that user's profiles.
fn authorize_privileged(peer: &Peer, target_user_uid: u32) -> bool {
    peer.uid == 0 || peer.uid == target_user_uid
}

#[allow(dead_code)]
fn handle(req: Request, _peer: &Peer) -> Response {
    match req {
        Request::Ping => Response::Pong,
        Request::Authenticate { .. } => {
            // TODO: capture RGB+IR -> detect -> align -> embed -> liveness gate
            //       -> matcher.verify(threshold) -> on pass, unseal secret.
            Response::Error("unimplemented".into())
        }
        Request::Enroll { .. }
        | Request::DeleteProfile { .. }
        | Request::ListProfiles { .. }
        | Request::SelfTest { .. } => Response::Error("unimplemented".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_and_self_authorized_others_denied() {
        let root = Peer { uid: 0, gid: 0, pid: 1 };
        let alice = Peer { uid: 1000, gid: 1000, pid: 2 };
        let mallory = Peer { uid: 1001, gid: 1001, pid: 3 };
        assert!(authorize_privileged(&root, 1000));
        assert!(authorize_privileged(&alice, 1000));
        assert!(!authorize_privileged(&mallory, 1000));
    }
}
