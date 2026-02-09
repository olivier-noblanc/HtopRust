use ratatui::style::Color;

pub struct Theme {
    pub background: Color,
    pub text: Color,
    pub error: Color,
    pub success: Color,
    pub warning: Color,
    pub highlight: Color,
    pub header_bg: Color,
    #[allow(dead_code)]
    pub header_fg: Color,
    #[allow(dead_code)]
    pub border: Color,
    #[allow(dead_code)]
    pub selection_bg: Color,
    pub network: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            background: Color::Rgb(0, 0, 0),
            text: Color::White,
            error: Color::Red,
            success: Color::Green,
            warning: Color::Yellow,
            highlight: Color::Cyan, 
            header_bg: Color::Rgb(20, 20, 20),
            header_fg: Color::Green, 
            border: Color::White,
            selection_bg: Color::Rgb(40, 40, 40),
            network: Color::Magenta,
        }
    }
}
