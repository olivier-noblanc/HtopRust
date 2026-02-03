use std::env;

fn main() {
    // Compiler les ressources Windows (icône et métadonnées)
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("icon.ico");
        res.set("FileDescription", "System Monitor for Windows");
        res.set("ProductName", "HtopRust");
        res.set("CompanyName", "Olivier Noblanc");
        res.set("LegalCopyright", "Copyright (C) 2026 Olivier Noblanc");
        res.set("OriginalFilename", "HtopRust.exe");
        res.set("InternalName", "HtopRust.exe");
        // Tentative d'ajout d'un champ Author personnalisé (certains outils le lisent)
        res.set("Author", "Olivier Noblanc");
        res.compile().unwrap();
    }
}
