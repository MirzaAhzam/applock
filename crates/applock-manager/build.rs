//! Build script compiling the Slint Manager UI.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    slint_build::compile("../../ui/manager/manager.slint")?;
    Ok(())
}
