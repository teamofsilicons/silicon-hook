/**
 * Syntax highlighting for code blocks, done on the server so a page ships its colours as plain spans. Copied from the
 * store (silicon-apps/store/lib/docs/highlight.ts): the developer site's highlighter (developer/lib/docs/highlight.ts)
 * with one addition, a PowerShell label (shown plain). Each
 * language gets a small lexer that understands what breaks naive highlighters in these docs: shell strings that run
 * over many lines (a curl -d '{…}' body), variables inside double quotes, heredocs, JavaScript regex literals and
 * template strings, Rust raw strings, lifetimes and macros, HTTP messages with a JSON body, TOML tables and HTML with
 * a <script>.
 *
 * Token kinds are the code-block roles of Silicon UI (components/silicon-ui/code-block), so the colours match the rest of the site.
 * Unknown languages, `text` and `output` stay plain.
 */

export type TokenKind = "comment" | "string" | "number" | "keyword" | "type" | "function" | "property" | "tag" | "punctuation";

export interface CodeToken {
  /** The role, or undefined for plain text. */
  k?: TokenKind;
  v: string;
}

const LABELS: Record<string, string> = {
  sh: "Shell", bash: "Shell", shell: "Shell", zsh: "Shell", console: "Shell", terminal: "Shell",
  json: "JSON", jsonc: "JSON", json5: "JSON",
  rust: "Rust", rs: "Rust",
  ts: "TypeScript", typescript: "TypeScript", tsx: "TypeScript", js: "JavaScript", javascript: "JavaScript", jsx: "JavaScript", mjs: "JavaScript", cjs: "JavaScript",
  powershell: "PowerShell", ps1: "PowerShell", pwsh: "PowerShell",
  http: "HTTP", toml: "TOML", html: "HTML", xml: "XML", svg: "SVG", csv: "CSV", yaml: "YAML", yml: "YAML", diff: "Diff", sql: "SQL",
  text: "Text", txt: "Text", plain: "Text", plaintext: "Text", output: "Output", "": "Text",
};

/** A name for the language, for the code block's header. */
export function languageLabel(lang: string): string {
  const key = lang.toLowerCase();
  return LABELS[key] ?? (key ? key.toUpperCase() : "Text");
}

/** PascalCase names are types; SCREAMING_CASE names are constants and stay plain. */
const isTypeName = (word: string) => /^[A-Z]/.test(word) && /[a-z]/.test(word);

class Out {
  tokens: CodeToken[] = [];

  push(value: string, kind?: TokenKind) {
    if (!value) return;
    const last = this.tokens[this.tokens.length - 1];
    if (last && last.k === kind) last.v += value;
    else this.tokens.push(kind ? { k: kind, v: value } : { v: value });
  }
}

/* ------------------------------------------------------------------------------------------------------------------
 * Shell
 * ------------------------------------------------------------------------------------------------------------------ */

const SHELL_KEYWORDS = new Set(["if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "in", "function", "select", "time", "return", "exit", "export", "local", "readonly", "declare", "set", "unset", "source", "trap", "shift", "break", "continue", "eval", "exec"]);
/** Words after which the next word is a command again (or an assignment): `if curl …`, `sudo env X=1 cmd`, `export X=1`. */
const COMMAND_RESET = new Set(["if", "then", "do", "else", "elif", "while", "until", "time", "!", "sudo", "env", "exec", "nohup", "xargs", "command", "builtin", "export", "local", "readonly", "declare"]);

function shellVariable(code: string, at: number): number {
  // $NAME, ${…}, $1, $?, $@, $#, $$, $!, $(…) handled by the caller.
  if (code[at + 1] === "{") {
    const close = code.indexOf("}", at + 2);
    return close < 0 ? code.length : close + 1;
  }
  const name = /^\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9?@#$!*-])/.exec(code.slice(at, at + 64));
  return name ? at + name[0].length : at;
}

function highlightShell(code: string, out: Out) {
  let index = 0;
  let commandStart = true;
  let parenDepth: number[] = [];
  const heredocs: Array<{ word: string; strip: boolean }> = [];

  while (index < code.length) {
    const char = code[index]!;

    if (char === "\n") {
      out.push("\n");
      index++;
      // Heredoc bodies start on the next line and run to their delimiter line.
      while (heredocs.length) {
        const { word, strip } = heredocs.shift()!;
        let end = index;
        for (;;) {
          const lineEnd = code.indexOf("\n", end);
          const line = code.slice(end, lineEnd < 0 ? code.length : lineEnd);
          if ((strip ? line.trimStart() : line) === word) {
            out.push(code.slice(index, end), "string");
            out.push(line, "keyword");
            index = end + line.length;
            if (index < code.length) {
              out.push("\n");
              index++;
            }
            break;
          }
          if (lineEnd < 0) {
            out.push(code.slice(index), "string");
            index = code.length;
            break;
          }
          end = lineEnd + 1;
        }
      }
      commandStart = true;
      continue;
    }
    if (char === " " || char === "\t") {
      let end = index;
      while (code[end] === " " || code[end] === "\t") end++;
      out.push(code.slice(index, end));
      index = end;
      continue;
    }
    if (char === "\\" && code[index + 1] === "\n") {
      out.push("\\", "punctuation");
      out.push("\n");
      index += 2;
      continue;
    }
    if (char === "#" && (index === 0 || /\s/.test(code[index - 1]!))) {
      const end = code.indexOf("\n", index);
      out.push(code.slice(index, end < 0 ? code.length : end), "comment");
      index = end < 0 ? code.length : end;
      continue;
    }
    if (char === "'") {
      const close = code.indexOf("'", index + 1);
      const end = close < 0 ? code.length : close + 1;
      out.push(code.slice(index, end), "string");
      index = end;
      commandStart = false;
      continue;
    }
    if (char === "$" && code[index + 1] === "'") {
      let end = index + 2;
      while (end < code.length && code[end] !== "'") end += code[end] === "\\" ? 2 : 1;
      out.push(code.slice(index, Math.min(end + 1, code.length)), "string");
      index = Math.min(end + 1, code.length);
      continue;
    }
    if (char === "\"") {
      // Double quotes: literal text in string colour, $VARIABLES inside in variable colour.
      out.push("\"", "string");
      index++;
      while (index < code.length && code[index] !== "\"") {
        if (code[index] === "\\") {
          out.push(code.slice(index, index + 2), "string");
          index += 2;
          continue;
        }
        if (code[index] === "$" && code[index + 1] !== "(") {
          const end = shellVariable(code, index);
          if (end > index) {
            out.push(code.slice(index, end), "property");
            index = end;
            continue;
          }
        }
        out.push(code[index]!, "string");
        index++;
      }
      if (index < code.length) {
        out.push("\"", "string");
        index++;
      }
      commandStart = false;
      continue;
    }
    if (char === "$" && code[index + 1] === "(") {
      out.push("$(", "punctuation");
      parenDepth.push(1);
      index += 2;
      commandStart = true;
      continue;
    }
    if (char === "$") {
      const end = shellVariable(code, index);
      if (end > index) {
        out.push(code.slice(index, end), "property");
        index = end;
        commandStart = false;
        continue;
      }
    }
    if (char === "<" && code[index + 1] === "<" && code[index + 2] !== "<") {
      const heredoc = /^<<(-?)[ \t]*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2/.exec(code.slice(index));
      if (heredoc) {
        out.push(heredoc[0], "punctuation");
        heredocs.push({ word: heredoc[3]!, strip: heredoc[1] === "-" });
        index += heredoc[0].length;
        continue;
      }
    }
    const operator = /^(?:&&|\|\||;;|[|;&]|[0-9]*>>?(?:&[0-9])?|<|\(|\)|\{|\})/.exec(code.slice(index, index + 4));
    // Braces are a group only where a command could start or when they stand alone ({ cmd; }); elsewhere text.
    const braceIsOperator = (char !== "{" && char !== "}") || commandStart || /[\s;]/.test(code[index + 1] ?? " ");
    if (operator && braceIsOperator) {
      const value = operator[0];
      out.push(value, "punctuation");
      index += value.length;
      if (value === ")" && parenDepth.length) parenDepth = parenDepth.slice(0, -1);
      if (/^(?:&&|\|\||[|;&(]|;;|\{)$/.test(value)) commandStart = true;
      continue;
    }

    // A word: up to whitespace, a quote, a variable or an operator.
    let end = index;
    while (end < code.length && !/[\s'"$|;&<>()`]/.test(code[end]!) && !(code[end] === "\\" && code[end + 1] === "\n")) {
      if (code[end] === "\\") end++;
      end++;
    }
    if (end === index) {
      out.push(char);
      index++;
      continue;
    }
    const word = code.slice(index, end);
    if (commandStart) {
      const assignment = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(word);
      if (assignment) {
        out.push(assignment[1]!, "property");
        out.push("=", "punctuation");
        out.push(word.slice(assignment[0].length), /^\d+$/.test(word.slice(assignment[0].length)) ? "number" : undefined);
        index = end;
        continue; // still at a command start: VAR=1 command …
      }
      out.push(word, SHELL_KEYWORDS.has(word) ? "keyword" : "function");
      commandStart = COMMAND_RESET.has(word);
    } else if (/^--?[A-Za-z0-9][\w-]*(=|$)/.test(word)) {
      const equals = word.indexOf("=");
      if (equals > 0) {
        out.push(word.slice(0, equals), "type");
        out.push("=", "punctuation");
        out.push(word.slice(equals + 1));
      } else {
        out.push(word, "type");
      }
    } else if (/^-?\d+(?:\.\d+)?$/.test(word)) {
      out.push(word, "number");
    } else {
      out.push(word);
    }
    index = end;
  }
}

/* ------------------------------------------------------------------------------------------------------------------
 * JSON
 * ------------------------------------------------------------------------------------------------------------------ */

function highlightJson(code: string, out: Out) {
  const pattern = /("(?:[^"\\\n]|\\.)*"?)|(\/\/[^\n]*|\/\*[\s\S]*?\*\/)|(-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b)|\b(true|false|null)\b|([{}[\],:])/g;
  let last = 0;
  for (const match of code.matchAll(pattern)) {
    const at = match.index!;
    if (at > last) out.push(code.slice(last, at));
    const [whole, string, comment, number, literal] = match;
    if (string) out.push(whole, /^\s*:/.test(code.slice(at + whole.length)) ? "property" : "string");
    else if (comment) out.push(whole, "comment");
    else if (number) out.push(whole, "number");
    else if (literal) out.push(whole, "keyword");
    else out.push(whole, "punctuation");
    last = at + whole.length;
  }
  if (last < code.length) out.push(code.slice(last));
}

/* ------------------------------------------------------------------------------------------------------------------
 * Rust
 * ------------------------------------------------------------------------------------------------------------------ */

const RUST_KEYWORDS = new Set(["as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where", "while", "Some", "None", "Ok", "Err"]);
const RUST_TYPES = new Set(["u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "f32", "f64", "bool", "char", "str", "Self", "String", "Vec", "Option", "Result", "Box"]);

function highlightRust(code: string, out: Out) {
  let index = 0;
  let previous = "";
  while (index < code.length) {
    const rest = code.slice(index);
    let match: RegExpExecArray | null;
    if ((match = /^\/\/[^\n]*/.exec(rest)) || (match = /^\/\*[\s\S]*?(?:\*\/|$)/.exec(rest))) {
      out.push(match[0], "comment");
    } else if ((match = /^b?r(#*)"[\s\S]*?"\1/.exec(rest))) {
      out.push(match[0], "string");
    } else if ((match = /^b?"(?:[^"\\]|\\[\s\S])*"?/.exec(rest))) {
      out.push(match[0], "string");
    } else if ((match = /^b?'(?:\\(?:u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'/.exec(rest))) {
      out.push(match[0], "string");
    } else if ((match = /^'[A-Za-z_][A-Za-z0-9_]*/.exec(rest))) {
      out.push(match[0], "keyword"); // a lifetime
    } else if ((match = /^(?:0x[0-9a-fA-F_]+|0o[0-7_]+|0b[01_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?)(?:[iu](?:8|16|32|64|128|size)|f32|f64)?/.exec(rest))) {
      out.push(match[0], "number");
    } else if ((match = /^[A-Za-z_][A-Za-z0-9_]*/.exec(rest))) {
      const word = match[0];
      const after = code.slice(index + word.length);
      if (RUST_KEYWORDS.has(word)) out.push(word, "keyword");
      else if (/^!\s*[([{]/.test(after)) out.push(word, "function"); // a macro: println!, vec!
      else if (RUST_TYPES.has(word) || isTypeName(word)) out.push(word, "type");
      else if (/^\s*(?:::\s*<[^>]*>\s*)?\(/.test(after)) out.push(word, "function");
      else if (previous === ".") out.push(word, "property");
      else out.push(word);
    } else if ((match = /^#!?\[/.exec(rest))) {
      out.push(match[0], "punctuation");
    } else if ((match = /^(?:::|->|=>|[{}()[\];,.:&*?!<>=+\-/%|^])/.exec(rest))) {
      out.push(match[0], "punctuation");
    } else {
      match = /^\s+|^./.exec(rest)!;
      out.push(match[0]);
    }
    if (!/^\s+$/.test(match[0])) previous = match[0];
    index += match[0].length;
  }
}

/* ------------------------------------------------------------------------------------------------------------------
 * TypeScript and JavaScript
 * ------------------------------------------------------------------------------------------------------------------ */

const JS_KEYWORDS = new Set(["as", "async", "await", "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else", "enum", "export", "extends", "false", "finally", "for", "from", "function", "get", "if", "implements", "import", "in", "instanceof", "interface", "let", "new", "null", "of", "private", "protected", "public", "readonly", "return", "satisfies", "set", "static", "super", "switch", "this", "throw", "true", "try", "type", "typeof", "undefined", "var", "void", "while", "with", "yield", "declare", "keyof", "namespace", "abstract"]);
const JS_TYPES = new Set(["string", "number", "boolean", "object", "symbol", "bigint", "unknown", "never", "any", "void", "Record", "Promise", "Array", "Map", "Set", "Date", "Error", "Response", "Request", "URL", "URLSearchParams", "Uint8Array", "Buffer"]);
/** After these tokens a `/` starts a regular expression rather than dividing. */
const REGEX_AFTER = /^(?:[(,=:[!&|?{};+\-*%<>~^]|=>|return|typeof|case|do|else|in|of|new|delete|void|throw|yield|await)$/;

function highlightScript(code: string, out: Out, start = 0, stopAtBrace = false): number {
  let index = start;
  let previous = "";
  let depth = 0;
  while (index < code.length) {
    const char = code[index]!;
    if (stopAtBrace) {
      if (char === "{") depth++;
      if (char === "}") {
        if (depth === 0) return index;
        depth--;
      }
    }
    const rest = code.slice(index, index + 4096);
    let match: RegExpExecArray | null;
    let kind: TokenKind | undefined;
    if ((match = /^\/\/[^\n]*/.exec(rest)) || (match = /^\/\*[\s\S]*?(?:\*\/|$)/.exec(rest))) {
      kind = "comment";
    } else if (char === "`") {
      // A template literal: text in string colour, ${expressions} highlighted as code.
      out.push("`", "string");
      index++;
      while (index < code.length && code[index] !== "`") {
        if (code[index] === "\\") {
          out.push(code.slice(index, index + 2), "string");
          index += 2;
        } else if (code[index] === "$" && code[index + 1] === "{") {
          out.push("${", "punctuation");
          index = highlightScript(code, out, index + 2, true);
          if (code[index] === "}") {
            out.push("}", "punctuation");
            index++;
          }
        } else {
          out.push(code[index]!, "string");
          index++;
        }
      }
      if (index < code.length) {
        out.push("`", "string");
        index++;
      }
      previous = "`";
      continue;
    } else if ((match = /^"(?:[^"\\\n]|\\.)*"?/.exec(rest)) || (match = /^'(?:[^'\\\n]|\\.)*'?/.exec(rest))) {
      kind = "string";
    } else if (char === "/" && (previous === "" || REGEX_AFTER.test(previous)) && (match = /^\/(?![*/])(?:[^/\\\n[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+\/[dgimsuyv]*/.exec(rest))) {
      kind = "string";
    } else if ((match = /^(?:0[xX][0-9a-fA-F_]+|\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?n?)/.exec(rest))) {
      kind = "number";
    } else if ((match = /^[A-Za-z_$][\w$]*/.exec(rest))) {
      const word = match[0];
      const after = code.slice(index + word.length, index + word.length + 64);
      if (previous === "." && /^\s*\(/.test(after)) kind = "function";
      else if (previous === "." || previous === "?.") kind = "property";
      else if (JS_KEYWORDS.has(word)) kind = "keyword";
      else if (JS_TYPES.has(word) || isTypeName(word) && !/^\s*\(/.test(after)) kind = "type";
      else if (/^\s*(?:<[^>()]*>)?\s*\(/.test(after)) kind = "function";
      else if (/^\s*:(?!:)/.test(after) && (previous === "{" || previous === ",")) kind = "property";
    } else if ((match = /^(?:\?\.|=>|===|!==|==|!=|<=|>=|&&|\|\||\?\?|\.\.\.|[{}()[\];,.:?!<>=+\-*/%&|^~])/.exec(rest))) {
      kind = "punctuation";
    } else {
      match = /^\s+|^./.exec(rest)!;
    }
    out.push(match[0], kind);
    if (!/^\s+$/.test(match[0])) previous = match[0];
    index += match[0].length;
  }
  return index;
}

/* ------------------------------------------------------------------------------------------------------------------
 * HTTP, TOML, HTML, CSV, YAML, diff
 * ------------------------------------------------------------------------------------------------------------------ */

function highlightHttp(code: string, out: Out) {
  const lines = code.split("\n");
  let body = -1;
  lines.forEach((line, index) => {
    if (index > 0) out.push("\n");
    if (body >= 0) return;
    if (index === 0) {
      const request = /^([A-Z]+)(\s+)(\S+)(\s+)(HTTP\/[\d.]+)?(.*)$/.exec(line);
      const status = /^(HTTP\/[\d.]+)(\s+)(\d{3})(.*)$/.exec(line);
      if (status) {
        out.push(status[1]!, "type");
        out.push(status[2]!);
        out.push(status[3]!, "number");
        out.push(status[4]!);
      } else if (request) {
        out.push(request[1]!, "keyword");
        out.push(request[2]!);
        out.push(request[3]!, "string");
        out.push(request[4]!);
        out.push(request[5] ?? "", "type");
        out.push(request[6]!);
      } else {
        out.push(line);
      }
      return;
    }
    if (!line.trim()) {
      body = index;
      return;
    }
    const header = /^([A-Za-z0-9-]+)(:)(.*)$/.exec(line);
    if (header) {
      out.push(header[1]!, "property");
      out.push(header[2]!, "punctuation");
      out.push(header[3]!);
    } else {
      out.push(line);
    }
  });
  if (body >= 0) {
    const content = lines.slice(body + 1).join("\n");
    if (/^\s*[[{]/.test(content)) highlightJson(content, out);
    else out.push(content);
  }
}

function highlightToml(code: string, out: Out) {
  code.split("\n").forEach((line, index) => {
    if (index > 0) out.push("\n");
    let match: RegExpExecArray | null;
    if ((match = /^(\s*)(\[\[?[^\]]+\]\]?)(.*)$/.exec(line))) {
      out.push(match[1]!);
      out.push(match[2]!, "type");
      out.push(match[3]!, "comment");
      return;
    }
    if ((match = /^(\s*)([A-Za-z0-9_.-]+|"[^"]*")(\s*=\s*)(.*)$/.exec(line))) {
      out.push(match[1]!);
      out.push(match[2]!, "property");
      out.push(match[3]!, "punctuation");
      tomlValue(match[4]!, out);
      return;
    }
    tomlValue(line, out);
  });
}

function tomlValue(value: string, out: Out) {
  const pattern = /("(?:[^"\\]|\\.)*"|'[^']*')|(#.*$)|(\b\d{4}-\d{2}-\d{2}(?:[T ][\d:.]+(?:Z|[+-]\d{2}:\d{2})?)?\b|[+-]?\b\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?\b)|\b(true|false)\b|([[\]{},=])/g;
  let last = 0;
  for (const match of value.matchAll(pattern)) {
    const at = match.index!;
    if (at > last) out.push(value.slice(last, at));
    const kind: TokenKind = match[1] ? "string" : match[2] ? "comment" : match[3] ? "number" : match[4] ? "keyword" : "punctuation";
    out.push(match[0], kind);
    last = at + match[0].length;
  }
  if (last < value.length) out.push(value.slice(last));
}

function highlightHtml(code: string, out: Out) {
  let index = 0;
  while (index < code.length) {
    const rest = code.slice(index);
    let match: RegExpExecArray | null;
    if ((match = /^<!--[\s\S]*?(?:-->|$)/.exec(rest))) {
      out.push(match[0], "comment");
      index += match[0].length;
      continue;
    }
    if ((match = /^<(\/?)([A-Za-z][\w:-]*)/.exec(rest))) {
      const name = match[2]!.toLowerCase();
      out.push(`<${match[1]}`, "punctuation");
      out.push(match[2]!, "tag");
      index += match[0].length;
      // Attributes up to the end of the tag.
      while (index < code.length && code[index] !== ">") {
        const attribute = /^(\s+)|^([^\s=>/"']+)|^(=)|^("[^"]*"|'[^']*')|^(\/)/.exec(code.slice(index));
        if (!attribute) {
          out.push(code[index]!);
          index++;
          continue;
        }
        const [whole, space, attrName, equals, quoted] = attribute;
        out.push(whole, space ? undefined : attrName ? "property" : equals ? "punctuation" : quoted ? "string" : "punctuation");
        index += whole.length;
      }
      if (code[index] === ">") {
        out.push(">", "punctuation");
        index++;
      }
      if (!match[1] && (name === "script" || name === "style")) {
        const close = code.toLowerCase().indexOf(`</${name}`, index);
        const end = close < 0 ? code.length : close;
        if (name === "script") highlightScript(code.slice(index, end), out);
        else out.push(code.slice(index, end));
        index = end;
      }
      continue;
    }
    const text = /^[^<]+|^</.exec(rest)!;
    out.push(text[0]);
    index += text[0].length;
  }
}

function highlightCsv(code: string, out: Out) {
  code.split("\n").forEach((line, index) => {
    if (index > 0) out.push("\n");
    line.split(/(,)/).forEach(part => out.push(part, part === "," ? "punctuation" : index === 0 ? "property" : /^"/.test(part) ? "string" : undefined));
  });
}

function highlightYaml(code: string, out: Out) {
  code.split("\n").forEach((line, index) => {
    if (index > 0) out.push("\n");
    const match = /^(\s*)(- )?([A-Za-z0-9_."'-]+)(:)(\s|$)(.*)$/.exec(line);
    if (/^\s*#/.test(line)) {
      out.push(line, "comment");
    } else if (match) {
      out.push(match[1]!);
      out.push(match[2] ?? "", "punctuation");
      out.push(match[3]!, "property");
      out.push(match[4]!, "punctuation");
      out.push(match[5]!);
      tomlValue(match[6]!, out);
    } else {
      const item = /^(\s*)(- )(.*)$/.exec(line);
      if (item) {
        out.push(item[1]!);
        out.push(item[2]!, "punctuation");
        tomlValue(item[3]!, out);
      } else {
        tomlValue(line, out);
      }
    }
  });
}

function highlightDiff(code: string, out: Out) {
  code.split("\n").forEach((line, index) => {
    if (index > 0) out.push("\n");
    out.push(line, line.startsWith("@@") ? "keyword" : line.startsWith("+") ? "string" : line.startsWith("-") ? "function" : undefined);
  });
}

/** Highlights `code` written in `lang` (a code fence's language). */
export function highlight(code: string, lang: string): CodeToken[] {
  const out = new Out();
  switch (lang.toLowerCase()) {
    case "sh": case "bash": case "shell": case "zsh": case "console": case "terminal":
      highlightShell(code, out);
      break;
    case "json": case "jsonc": case "json5":
      highlightJson(code, out);
      break;
    case "rust": case "rs":
      highlightRust(code, out);
      break;
    case "ts": case "typescript": case "tsx": case "js": case "javascript": case "jsx": case "mjs": case "cjs":
      highlightScript(code, out);
      break;
    case "http":
      highlightHttp(code, out);
      break;
    case "toml":
      highlightToml(code, out);
      break;
    case "html": case "xml": case "svg":
      highlightHtml(code, out);
      break;
    case "csv":
      highlightCsv(code, out);
      break;
    case "yaml": case "yml":
      highlightYaml(code, out);
      break;
    case "diff":
      highlightDiff(code, out);
      break;
    default:
      out.push(code);
  }
  return out.tokens;
}
