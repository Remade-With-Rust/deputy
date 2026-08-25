//! Desktop chrome: rounded forest-green app icon with a gold D, plus Windows title-bar tint.
//!
//! The icon is painted at runtime (no asset pipeline) so `cargo run` and a bundled exe share
//! the same mark. Corners are transparent so the taskbar tile reads as rounded.
#![allow(unsafe_code)] // `tint_caption` is a documented DwmSetWindowAttribute call.

use dioxus::desktop::tao::window::Icon;

/// Forest green from the in-app theme (`--rt-color-bg`).
const GREEN: [u8; 4] = [0x15, 0x1e, 0x18, 0xff];
/// Deep gold from the in-app theme (`--rt-color-accent`).
const GOLD: [u8; 4] = [0xb8, 0x86, 0x0b, 0xff];

/// 256px is a good ceiling for Windows `ICON_BIG` / the taskbar.
const ICON_SIZE: u32 = 256;

pub fn window_icon() -> Icon {
    Icon::from_rgba(paint_icon(ICON_SIZE), ICON_SIZE, ICON_SIZE)
        .expect("icon RGBA is always well-formed")
}

/// Paint a rounded square in theme green with a gold **D**.
pub fn paint_icon(size: u32) -> Vec<u8> {
    let s = size as f32;
    let mut out = vec![0u8; (size as usize) * (size as usize) * 4];
    let radius = s * 0.22;
    let hw = s * 0.5;
    for y in 0..size {
        for x in 0..size {
            let mut r_acc = 0.0;
            let mut g_acc = 0.0;
            let mut b_acc = 0.0;
            let mut a_acc = 0.0;
            // 2×2 supersample so the rounded edge and D stay clean when Windows scales the icon.
            for oy in [0.25, 0.75] {
                for ox in [0.25, 0.75] {
                    let px = x as f32 + ox;
                    let py = y as f32 + oy;
                    let (r, g, b, a) = sample(px, py, s, hw, radius);
                    r_acc += r;
                    g_acc += g;
                    b_acc += b;
                    a_acc += a;
                }
            }
            let i = ((y * size + x) * 4) as usize;
            out[i] = (r_acc * 0.25) as u8;
            out[i + 1] = (g_acc * 0.25) as u8;
            out[i + 2] = (b_acc * 0.25) as u8;
            out[i + 3] = (a_acc * 0.25) as u8;
        }
    }
    out
}

fn sample(px: f32, py: f32, s: f32, hw: f32, radius: f32) -> (f32, f32, f32, f32) {
    let dx = px - hw;
    let dy = py - hw;
    let sd = sd_rounded_box(dx, dy, hw, hw, radius);
    let cover = (0.5 - sd).clamp(0.0, 1.0);
    if cover <= 0.0 {
        return (0.0, 0.0, 0.0, 0.0);
    }
    let d = d_coverage(px / s, py / s);
    let (r, g, b) = if d > 0.0 {
        mix(GREEN, GOLD, d)
    } else {
        (GREEN[0] as f32, GREEN[1] as f32, GREEN[2] as f32)
    };
    (r * cover, g * cover, b * cover, 255.0 * cover)
}

fn mix(a: [u8; 4], b: [u8; 4], t: f32) -> (f32, f32, f32) {
    let t = t.clamp(0.0, 1.0);
    (
        a[0] as f32 + (b[0] as f32 - a[0] as f32) * t,
        a[1] as f32 + (b[1] as f32 - a[1] as f32) * t,
        a[2] as f32 + (b[2] as f32 - a[2] as f32) * t,
    )
}

/// Signed distance to a rounded rectangle centered at the origin.
fn sd_rounded_box(px: f32, py: f32, hw: f32, hh: f32, r: f32) -> f32 {
    let qx = px.abs() - hw + r;
    let qy = py.abs() - hh + r;
    qx.max(0.0).hypot(qy.max(0.0)) + qx.min(0.0).max(qy.min(0.0)) - r
}

/// Coverage of a filled capital D in unit-square coordinates (origin top-left).
fn d_coverage(nx: f32, ny: f32) -> f32 {
    let stem_left = 0.30;
    let stem_right = 0.44;
    let top = 0.22;
    let bot = 0.78;
    let in_stem = nx >= stem_left && nx <= stem_right && ny >= top && ny <= bot;

    let cx = 0.44;
    let cy = 0.50;
    let rx_out = 0.28;
    let ry_out = 0.28;
    let rx_in = 0.15;
    let ry_in = 0.15;
    let dx = nx - cx;
    let dy = ny - cy;
    let on_bowl = dx >= -0.04;
    let outer = (dx / rx_out).powi(2) + (dy / ry_out).powi(2) <= 1.0;
    let inner = (dx / rx_in).powi(2) + (dy / ry_in).powi(2) <= 1.0;
    if in_stem || (on_bowl && outer && !inner) {
        1.0
    } else {
        0.0
    }
}

/// Tint the native Windows caption to the app green and install the large taskbar icon.
#[cfg(target_os = "windows")]
pub fn apply_windows_chrome(window: &dioxus::desktop::tao::window::Window, icon: &Icon) {
    use dioxus::desktop::tao::platform::windows::WindowExtWindows;
    window.set_taskbar_icon(Some(icon.clone()));
    tint_caption(window.hwnd());
}

/// COLORREF is 0x00BBGGRR. `#151e18` → B=0x18 G=0x1e R=0x15.
#[cfg(target_os = "windows")]
fn tint_caption(hwnd: isize) {
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR,
        DWMWA_USE_IMMERSIVE_DARK_MODE,
    };

    let hwnd = hwnd as HWND;
    let dark: i32 = 1;
    let caption: u32 = 0x0018_1e_15;
    let text: u32 = 0x00e2_eb_e2;
    // Safety: HWND is the live tao window; each attribute pointer matches `cbattribute`.
    unsafe {
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE as u32,
            (&dark as *const i32).cast(),
            4,
        );
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_CAPTION_COLOR as u32,
            (&caption as *const u32).cast(),
            4,
        );
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_TEXT_COLOR as u32,
            (&text as *const u32).cast(),
            4,
        );
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_BORDER_COLOR as u32,
            (&caption as *const u32).cast(),
            4,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_buffer_matches_size() {
        let px = paint_icon(32);
        assert_eq!(px.len(), 32 * 32 * 4);
    }

    #[test]
    fn corners_are_transparent_so_the_tile_reads_round() {
        let px = paint_icon(64);
        let corner = |x: u32, y: u32| {
            let i = ((y * 64 + x) * 4) as usize;
            px[i + 3]
        };
        assert_eq!(corner(0, 0), 0);
        assert_eq!(corner(63, 0), 0);
        assert_eq!(corner(0, 63), 0);
        assert_eq!(corner(63, 63), 0);
    }

    #[test]
    fn center_is_opaque_theme_green() {
        let px = paint_icon(64);
        let i = ((32 * 64 + 32) * 4) as usize;
        assert_eq!(px[i + 3], 255);
        assert!(px[i + 1] > px[i], "green channel leads on the field");
    }

    #[test]
    fn gold_d_is_present() {
        let px = paint_icon(64);
        let gold = (0..64usize)
            .flat_map(|y| (0..64usize).map(move |x| (x, y)))
            .any(|(x, y)| {
                let i = (y * 64 + x) * 4;
                px[i] > 140 && px[i + 1] > 90 && px[i + 2] < 40 && px[i + 3] > 200
            });
        assert!(gold, "expected gold pixels forming the D");
    }
}
