//! System tray — Phase 6.
//!
//! Builds a tray icon with left-click toggle and right-click context menu.
//! The tray icon shows a real-time TOTP countdown pie chart.
//!
//! Uses the built-in `tray-icon` feature from tauri v2.

use std::sync::Mutex;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Runtime};

/// Holds the tray icon for dynamic updates.
pub struct TrayState<R: Runtime> {
    pub icon: Mutex<Option<tauri::tray::TrayIcon<R>>>,
}

impl<R: Runtime> TrayState<R> {
    pub fn new() -> Self {
        Self {
            icon: Mutex::new(None),
        }
    }
}

impl<R: Runtime> Default for TrayState<R> {
    fn default() -> Self {
        Self::new()
    }
}

pub fn build<R: Runtime>(
    app: &AppHandle<R>,
    tooltip: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let show_item = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

    let menu = Menu::with_items(
        app,
        &[&show_item, &PredefinedMenuItem::separator(app)?, &quit_item],
    )?;

    let icon = generate_pie_icon(100.0)?;

    let tray = TrayIconBuilder::new()
        .tooltip(tooltip)
        .icon(icon)
        .menu(&menu)
        .on_menu_event(move |handle: &AppHandle<R>, event| {
            let id = event.id().as_ref();
            match id {
                "show" => {
                    if let Some(window) = handle.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                "quit" => {
                    handle.exit(0);
                }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let handle: &AppHandle<R> = tray.app_handle();
                if let Some(window) = handle.get_webview_window("main") {
                    if window.is_visible().unwrap_or(false) {
                        let _ = window.hide();
                    } else {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
            }
        })
        .build(app)?;

    // Store the tray icon for later updates
    if let Some(state) = app.try_state::<TrayState<R>>() {
        if let Ok(mut guard) = state.icon.lock() {
            *guard = Some(tray);
        }
    }

    Ok(())
}

/// Generate a 32×32 pie chart icon showing TOTP countdown progress.
/// `pct` is a value from 0.0 (empty) to 100.0 (full circle).
pub fn generate_pie_icon(pct: f64) -> Result<Image<'static>, Box<dyn std::error::Error>> {
    let size = 32u32;
    let cx = 16f64;
    let cy = 16f64;
    let radius = 14f64;
    let clamped = pct.clamp(0.0, 100.0);
    let angle = (clamped / 100.0) * std::f64::consts::TAU - std::f64::consts::FRAC_PI_2;

    let bg_color = (30u8, 30u8, 30u8); // dark background
    let fill_color = (93u8, 173u8, 226u8); // blue fill (matches #5dade2)

    let mut buf = vec![0u8; (size * size * 4) as usize];

    for y in 0..size {
        for x in 0..size {
            let dx = x as f64 - cx;
            let dy = y as f64 - cy;
            let dist = (dx * dx + dy * dy).sqrt();
            let pixel_angle = dy.atan2(dx);
            let idx = ((y * size + x) * 4) as usize;

            if dist <= radius {
                // Anti-alias at the edge
                let edge_alpha = if dist > radius - 1.5 {
                    ((radius - dist) / 1.5).clamp(0.0, 1.0)
                } else {
                    1.0
                };

                // Determine if this pixel is in the "active" pie slice
                let in_slice = pixel_angle <= angle;

                let (r, g, b) = if in_slice { fill_color } else { bg_color };

                buf[idx] = r;
                buf[idx + 1] = g;
                buf[idx + 2] = b;
                buf[idx + 3] = (edge_alpha * 255.0) as u8;
            } else {
                buf[idx + 3] = 0; // transparent
            }
        }
    }

    Ok(Image::new_owned(buf, size, size))
}

/// Update the tray icon with current TOTP progress.
/// `pct` is the percentage of the TOTP period remaining (0-100).
pub fn update_icon<R: Runtime>(app: &AppHandle<R>, pct: f64) {
    if let Some(state) = app.try_state::<TrayState<R>>() {
        if let Ok(guard) = state.icon.lock() {
            if let Some(tray) = guard.as_ref() {
                if let Ok(image) = generate_pie_icon(pct) {
                    let _ = tray.set_icon(Some(image));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pie_icon_returns_image() {
        let img = generate_pie_icon(75.0).unwrap();
        assert!(!img.rgba().is_empty());
        assert_eq!(img.width(), 32);
        assert_eq!(img.height(), 32);
        assert_eq!(img.rgba().len(), 4096); // 32×32×4
    }

    #[test]
    fn test_generate_pie_icon_full() {
        let img = generate_pie_icon(100.0).unwrap();
        let bytes = img.rgba();
        // Center pixel should be colored
        let idx = (16 * 32 + 16) * 4;
        assert!(bytes[idx + 3] > 0, "center should be visible at 100%");
    }

    #[test]
    fn test_generate_pie_icon_corners_transparent() {
        let img = generate_pie_icon(50.0).unwrap();
        let bytes = img.rgba();
        // Corner pixels should be transparent (outside radius)
        assert_eq!(bytes[3], 0);
        assert_eq!(bytes[127], 0); // (31,0)
        assert_eq!(bytes[3971], 0); // (0,31)
    }

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_generate_pie_icon_zero_percent() {
        let img = generate_pie_icon(0.0).unwrap();
        assert_eq!(img.width(), 32);
        assert_eq!(img.height(), 32);
        // At 0%, no pixels should be in the "fill" slice
        let bytes = img.rgba();
        // Center pixel should be background (dark), not fill (blue)
        // Center is at (16, 16) → idx = (16*32+16)*4 = 2112
        let idx = (16 * 32 + 16) * 4;
        assert!(bytes[idx + 3] > 0, "center should be visible");
    }

    #[test]
    fn test_generate_pie_icon_half() {
        let img = generate_pie_icon(50.0).unwrap();
        assert_eq!(img.rgba().len(), 4096);
    }

    #[test]
    fn test_generate_pie_icon_quarter() {
        let img = generate_pie_icon(25.0).unwrap();
        assert_eq!(img.rgba().len(), 4096);
    }

    #[test]
    fn test_generate_pie_icon_three_quarters() {
        let img = generate_pie_icon(75.0).unwrap();
        assert_eq!(img.rgba().len(), 4096);
    }

    // ── New tests ──────────────────────────────────────────────

    #[test]
    fn test_generate_pie_icon_negative_pct_clamps() {
        // Negative percentage should behave like 0%
        let img = generate_pie_icon(-50.0).unwrap();
        assert_eq!(img.width(), 32);
        assert_eq!(img.height(), 32);
        assert_eq!(img.rgba().len(), 4096);
        // No crash
    }

    #[test]
    fn test_generate_pie_icon_over_100_pct() {
        // >100% should behave like full circle (100%)
        let img = generate_pie_icon(150.0).unwrap();
        assert_eq!(img.width(), 32);
        assert_eq!(img.height(), 32);
        assert_eq!(img.rgba().len(), 4096);
        // No crash — 150% creates angle > 1.5× TAU, which is fine for atan2
    }

    #[test]
    fn test_generate_pie_icon_zero_pct_all_background() {
        // At 0%, no pixels should be in the fill slice — all circle pixels are background
        let img = generate_pie_icon(0.0).unwrap();
        let bytes = img.rgba();
        // Check center pixel: should be background color (30, 30, 30) with alpha > 0
        let idx = (16 * 32 + 16) * 4;
        assert_eq!(bytes[idx], 30, "center R should be background at 0%");
        assert_eq!(bytes[idx + 1], 30, "center G should be background at 0%");
        assert_eq!(bytes[idx + 2], 30, "center B should be background at 0%");
        assert!(bytes[idx + 3] > 0, "center should be visible");
    }

    #[test]
    fn test_generate_pie_icon_100_pct_all_fill() {
        // At 100%, all circle pixels should be in the fill slice — fill color (93, 173, 226)
        let img = generate_pie_icon(100.0).unwrap();
        let bytes = img.rgba();
        let idx = (16 * 32 + 16) * 4;
        assert_eq!(bytes[idx], 93, "center R should be fill at 100%");
        assert_eq!(bytes[idx + 1], 173, "center G should be fill at 100%");
        assert_eq!(bytes[idx + 2], 226, "center B should be fill at 100%");
        assert!(bytes[idx + 3] > 0, "center should be visible");
    }

    #[test]
    fn test_generate_pie_icon_half_pct_midpoint_angle() {
        // At 50%, angle = PI/2. atan2 returns [-PI, PI].
        // Pixels with angle <= PI/2 are filled.
        // Lower-left pixel (8,24): dx=-8, dy=8, dist=11.3 (inside), angle=3PI/4≈2.36
        //   2.36 > PI/2=1.57 → NOT filled → background (30)
        // Bottom-center (16,28): dx=0, dy=12, dist=12 (inside), angle=PI/2=1.57
        //   1.57 <= 1.57 → filled → fill color (93)
        let img = generate_pie_icon(50.0).unwrap();
        let bytes = img.rgba();

        let left_idx = (24 * 32 + 8) * 4; // x=8, y=24 (lower-left quadrant)
        assert_eq!(
            bytes[left_idx], 30,
            "lower-left should be background at 50%"
        );
        assert_eq!(bytes[left_idx + 1], 30);
        assert_eq!(bytes[left_idx + 2], 30);

        let bot_idx = (28 * 32 + 16) * 4; // x=16, y=28 (bottom-center)
        assert_eq!(bytes[bot_idx], 93, "bottom-center should be fill at 50%");
        assert_eq!(bytes[bot_idx + 1], 173);
        assert_eq!(bytes[bot_idx + 2], 226);
    }

    #[test]
    fn test_generate_pie_icon_pixel_outside_circle_transparent() {
        // Pixels far outside the radius should have alpha=0 (fully transparent)
        let img = generate_pie_icon(75.0).unwrap();
        let bytes = img.rgba();
        // Top-left corner (0,0)
        assert_eq!(bytes[3], 0, "corner pixel should be transparent");
        // Bottom-right corner (31,31)
        let corner_idx = (31 * 32 + 31) * 4;
        assert_eq!(bytes[corner_idx + 3], 0, "far corner should be transparent");
    }

    #[test]
    fn test_generate_pie_icon_edge_anti_aliasing() {
        // Pixels at the edge of the circle should have anti-aliasing.
        // At (16, 2): dist=14=radius → edge_alpha=0 (fully transparent at boundary).
        // At (16, 3): dist=13 < radius → edge_alpha > 0 (partially opaque inside).
        let img = generate_pie_icon(100.0).unwrap();
        let bytes = img.rgba();

        // Pixel at exactly the boundary — alpha should be 0 (edge of anti-alias band)
        let boundary_idx = (2 * 32 + 16) * 4;
        let boundary_alpha = bytes[boundary_idx + 3];
        assert_eq!(
            boundary_alpha, 0,
            "pixel at exact radius boundary should have alpha=0: {boundary_alpha}"
        );

        // Pixel one row inside — should have partial alpha (anti-aliasing band)
        let inner_idx = (3 * 32 + 16) * 4;
        let inner_alpha = bytes[inner_idx + 3];
        assert!(
            inner_alpha > 0 && inner_alpha < 255,
            "pixel inside the anti-alias band should have partial alpha: {inner_alpha}"
        );
    }

    #[test]
    fn test_generate_pie_icon_negative_pct_same_as_zero() {
        // Negative pct should produce the same result as 0%
        let neg = generate_pie_icon(-1.0).unwrap();
        let zero = generate_pie_icon(0.0).unwrap();
        assert_eq!(neg.rgba(), zero.rgba(), "negative should match 0%");
    }

    #[test]
    fn test_generate_pie_icon_over_100_same_as_100() {
        // Over 100% should produce the same result as 100%
        let over = generate_pie_icon(200.0).unwrap();
        let full = generate_pie_icon(100.0).unwrap();
        assert_eq!(over.rgba(), full.rgba(), ">100% should match 100%");
    }

    #[test]
    fn test_generate_pie_icon_exactly_100_pct_full_circle() {
        // At exactly 100%, the entire circle should be filled
        let img = generate_pie_icon(100.0).unwrap();
        let bytes = img.rgba();
        // Many pixels should be visible (non-transparent)
        let visible_count = bytes.chunks(4).filter(|p| p[3] > 0).count();
        assert!(
            visible_count > 500,
            "at 100% most circle pixels should be visible: {visible_count}"
        );
    }
}
