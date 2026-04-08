package ai.sentinel;

import java.util.*;

final class Json {
    private Json() {}

    static String stringify(Object value) {
        StringBuilder sb = new StringBuilder();
        write(value, sb);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void write(Object value, StringBuilder sb) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String) {
            sb.append('"').append(escape((String) value)).append('"');
        } else if (value instanceof Number || value instanceof Boolean) {
            sb.append(value);
        } else if (value instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<Object, Object> e : ((Map<Object, Object>) value).entrySet()) {
                if (!first) sb.append(',');
                write(String.valueOf(e.getKey()), sb);
                sb.append(':');
                write(e.getValue(), sb);
                first = false;
            }
            sb.append('}');
        } else if (value instanceof Iterable) {
            sb.append('[');
            boolean first = true;
            for (Object item : (Iterable<?>) value) {
                if (!first) sb.append(',');
                write(item, sb);
                first = false;
            }
            sb.append(']');
        } else if (value.getClass().isArray()) {
            sb.append('[');
            int len = java.lang.reflect.Array.getLength(value);
            for (int i = 0; i < len; i++) {
                if (i > 0) sb.append(',');
                write(java.lang.reflect.Array.get(value, i), sb);
            }
            sb.append(']');
        } else {
            write(String.valueOf(value), sb);
        }
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    static Object parse(String text) {
        return new Parser(text).parseValue();
    }

    private static final class Parser {
        private final String s;
        private int i = 0;
        Parser(String s) { this.s = s == null ? "" : s.trim(); }

        Object parseValue() {
            skip();
            if (i >= s.length()) return null;
            char c = s.charAt(i);
            if (c == '{') return parseObject();
            if (c == '[') return parseArray();
            if (c == '"') return parseString();
            if (c == 't' || c == 'f') return parseBoolean();
            if (c == 'n') { i += 4; return null; }
            return parseNumberOrBare();
        }

        private Map<String, Object> parseObject() {
            Map<String, Object> map = new LinkedHashMap<>();
            i++; skip();
            if (s.charAt(i) == '}') { i++; return map; }
            while (i < s.length()) {
                String key = parseString();
                skip(); i++; // colon
                Object value = parseValue();
                map.put(key, value);
                skip();
                if (s.charAt(i) == '}') { i++; break; }
                i++; // comma
            }
            return map;
        }

        private List<Object> parseArray() {
            List<Object> list = new ArrayList<>();
            i++; skip();
            if (s.charAt(i) == ']') { i++; return list; }
            while (i < s.length()) {
                list.add(parseValue());
                skip();
                if (s.charAt(i) == ']') { i++; break; }
                i++;
            }
            return list;
        }

        private String parseString() {
            StringBuilder out = new StringBuilder();
            i++; // opening quote
            while (i < s.length()) {
                char c = s.charAt(i++);
                if (c == '"') break;
                if (c == '\\' && i < s.length()) {
                    char n = s.charAt(i++);
                    switch (n) {
                        case 'n': out.append('\n'); break;
                        case 'r': out.append('\r'); break;
                        case 't': out.append('\t'); break;
                        case '"': out.append('"'); break;
                        case '\\': out.append('\\'); break;
                        default: out.append(n); break;
                    }
                } else {
                    out.append(c);
                }
            }
            return out.toString();
        }

        private Boolean parseBoolean() {
            if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
            i += 5; return Boolean.FALSE;
        }

        private Object parseNumberOrBare() {
            int start = i;
            while (i < s.length() && ",]} \n\r\t".indexOf(s.charAt(i)) == -1) i++;
            String token = s.substring(start, i);
            try {
                if (token.contains(".") || token.contains("e") || token.contains("E")) return Double.parseDouble(token);
                return Long.parseLong(token);
            } catch (NumberFormatException e) {
                return token;
            }
        }

        private void skip() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        }
    }
}
