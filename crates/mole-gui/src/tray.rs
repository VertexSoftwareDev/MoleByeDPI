//! The system-tray icon: keep Mole reachable while its window is hidden.
//!
//! Closing the window drops it to the tray instead of quitting, so the status and
//! the site checker are a click away without a taskbar entry. Left-click (or the
//! "Open" item) shows the window; "Quit" really exits. Events are polled each
//! frame from tray-icon's global receivers.

use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

pub enum TrayAction {
    None,
    Open,
    Quit,
}

pub struct Tray {
    _tray: TrayIcon,
    open_id: MenuId,
    quit_id: MenuId,
}

impl Tray {
    /// Build the tray icon. `open`/`quit` are the localized menu labels. Returns
    /// `None` if the platform refuses the icon or tray — the app still runs.
    pub fn new(
        rgba: Vec<u8>,
        w: u32,
        h: u32,
        tooltip: &str,
        open: &str,
        quit: &str,
    ) -> Option<Tray> {
        let open_item = MenuItem::with_id("open", open, true, None);
        let quit_item = MenuItem::with_id("quit", quit, true, None);
        let menu = Menu::new();
        menu.append_items(&[&open_item, &PredefinedMenuItem::separator(), &quit_item])
            .ok()?;
        let icon = Icon::from_rgba(rgba, w, h).ok()?;
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip(tooltip)
            .with_icon(icon)
            .with_menu_on_left_click(false) // left-click opens; right-click menus
            .build()
            .ok()?;
        Some(Tray {
            _tray: tray,
            open_id: open_item.id().clone(),
            quit_id: quit_item.id().clone(),
        })
    }

    pub fn set_tooltip(&self, tooltip: &str) {
        let _ = self._tray.set_tooltip(Some(tooltip));
    }

    /// Drain pending tray/menu events and return the action to take. A left-click
    /// up on the icon, or the "Open" item, means show the window; "Quit" exits.
    pub fn poll(&self) -> TrayAction {
        let mut action = TrayAction::None;
        while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = ev
            {
                action = TrayAction::Open;
            }
        }
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if ev.id == self.open_id {
                action = TrayAction::Open;
            } else if ev.id == self.quit_id {
                return TrayAction::Quit;
            }
        }
        action
    }
}
