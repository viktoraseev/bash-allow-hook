use std::io::Read;
fn dump(n: tree_sitter::Node, src: &[u8], d: usize) {
    let t = n.utf8_text(src).unwrap_or("").replace('\n', "\\n");
    let t: String = t.chars().take(40).collect();
    let field = "";
    println!("{}{}{} {:?}{}", "  ".repeat(d), if n.is_named() { "" } else { "'" }, n.kind(), t, field);
    let mut c = n.walk();
    for (i, ch) in n.children(&mut c).enumerate() {
        let f = n.field_name_for_child(i as u32).map(|f| format!("[{f}] ")).unwrap_or_default();
        print!("{}", if f.is_empty() { String::new() } else { format!("{}{}", "  ".repeat(d + 1), f) });
        if !f.is_empty() { println!(); }
        dump(ch, src, d + 1);
    }
}
fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).unwrap();
    let mut p = tree_sitter::Parser::new();
    p.set_language(&tree_sitter_bash::LANGUAGE.into()).unwrap();
    let t = p.parse(&s, None).unwrap();
    println!("has_error={}", t.root_node().has_error());
    dump(t.root_node(), s.as_bytes(), 0);
}
