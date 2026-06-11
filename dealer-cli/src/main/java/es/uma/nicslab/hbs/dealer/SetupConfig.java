package es.uma.nicslab.hbs.dealer;

import es.uma.nicslab.hbs.lms.LMOtsParameters;
import es.uma.nicslab.hbs.lms.LMSParameters;
import es.uma.nicslab.hbs.lms.LMSigParameters;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Lee y parsea el fichero setup-config.json.
 *
 * Formato esperado:
 * {
 *   "k": 3,
 *   "lmsParams":         "lms_sha256_n32_h5",
 *   "lmotsParams":       "sha256_n32_w4",
 *   "coalitionPattern":  [[0,1],[1,2],[0,2]]
 * }
 *
 * El patrón de coaliciones se repite cíclicamente hasta cubrir los D KeyIDs
 * que genera el árbol LMS (D = 2^h).
 *
 * Parámetros LMS soportados:
 *   lms_sha256_n32_h5  → 32 KeyIDs  (h=5,  rápido para pruebas)
 *   lms_sha256_n32_h10 → 1024 KeyIDs
 *   lms_sha256_n32_h15 → 32768 KeyIDs
 *   lms_sha256_n32_h20 → 1048576 KeyIDs
 *
 * Parámetros LM-OTS soportados:
 *   sha256_n32_w1, sha256_n32_w2, sha256_n32_w4, sha256_n32_w8
 */
public class SetupConfig {

    private final int k;
    private final LMSParameters lmsParameters;
    private final int[][] coalitionPattern;

    private SetupConfig(int k, LMSParameters lmsParameters, int[][] coalitionPattern) {
        this.k = k;
        this.lmsParameters = lmsParameters;
        this.coalitionPattern = coalitionPattern;
    }

    public static SetupConfig loadFrom(Path path) throws IOException {
        String json = Files.readString(path, StandardCharsets.UTF_8);

        int k = extractInt(json, "k");
        String lmsParamStr = extractString(json, "lmsParams");
        String lmotsParamStr = extractString(json, "lmotsParams");
        int[][] pattern = extractCoalitionPattern(json);

        LMSigParameters lmsSig = parseLMSigParameters(lmsParamStr);
        LMOtsParameters lmOts = parseLMOtsParameters(lmotsParamStr);
        LMSParameters lmsParams = new LMSParameters(lmsSig, lmOts);

        return new SetupConfig(k, lmsParams, pattern);
    }

    public int getK() {
        return k;
    }

    public LMSParameters getLmsParameters() {
        return lmsParameters;
    }

    /**
     * Expande el patrón de coaliciones hasta D KeyIDs de forma cíclica.
     * D se pasa como parámetro porque lo determina el árbol LMS generado.
     *
     * @param D Número total de KeyIDs (2^h).
     * @return coalitions[keyID] = índices de trustees de esa coalición.
     */
    public int[][] buildCoalitions(int D) {
        int[][] coalitions = new int[D][];
        for (int keyID = 0; keyID < D; keyID++) {
            coalitions[keyID] = coalitionPattern[keyID % coalitionPattern.length].clone();
        }
        return coalitions;
    }

    private static int extractInt(String json, String field) throws IOException {
        String key = "\"" + field + "\"";
        int keyIdx = json.indexOf(key);
        if (keyIdx < 0) {
            throw new IOException("Campo '" + field + "' no encontrado");
        }
        int colonIdx = json.indexOf(':', keyIdx + key.length());
        int start = colonIdx + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) {
            start++;
        }
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) {
            end++;
        }
        try {
            return Integer.parseInt(json.substring(start, end).trim());
        } catch (NumberFormatException e) {
            throw new IOException("Valor entero del campo '" + field + "' malformado");
        }
    }

    private static String extractString(String json, String field) throws IOException {
        String key = "\"" + field + "\"";
        int keyIdx  = json.indexOf(key);
        if (keyIdx < 0) {
            throw new IOException("Campo '" + field + "' no encontrado");
        }
        int colonIdx = json.indexOf(':', keyIdx + key.length());
        int openIdx  = json.indexOf('"', colonIdx + 1);
        int closeIdx = json.indexOf('"', openIdx + 1);
        if (openIdx < 0 || closeIdx < 0) {
            throw new IOException("Valor del campo '" + field + "' malformado");
        }
        return json.substring(openIdx + 1, closeIdx);
    }

    /**
     * Parsea el array de arrays de coalitionPattern.
     * Formato esperado: [[0,1],[1,2],[0,2]]
     */
    private static int[][] extractCoalitionPattern(String json) throws IOException {
        String key = "\"coalitionPattern\"";
        int keyIdx = json.indexOf(key);
        if (keyIdx < 0) {
            throw new IOException("Campo 'coalitionPattern' no encontrado");
        }

        int outerOpen = json.indexOf('[', keyIdx + key.length());
        int outerClose = findMatchingBracket(json, outerOpen);
        String outerContent = json.substring(outerOpen + 1, outerClose).trim();

        List<int[]> pattern = new ArrayList<>();
        int pos = 0;
        while (pos < outerContent.length()) {
            int innerOpen = outerContent.indexOf('[', pos);
            if (innerOpen < 0) break;
            int innerClose = findMatchingBracket(outerContent, innerOpen);
            String innerContent = outerContent.substring(innerOpen + 1, innerClose).trim();
            pattern.add(parseIntArray(innerContent));
            pos = innerClose + 1;
        }

        if (pattern.isEmpty()) {
            throw new IOException("coalitionPattern no puede estar vacío");
        }

        return pattern.toArray(new int[0][]);
    }

    private static int[] parseIntArray(String content) throws IOException {
        if (content.isBlank()) return new int[0];
        String[] parts = content.split(",");
        int[] result = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            try {
                result[i] = Integer.parseInt(parts[i].trim());
            } catch (NumberFormatException e) {
                throw new IOException("Índice de trustee inválido: '" + parts[i].trim() + "'");
            }
        }
        return result;
    }

    /**
     * Encuentra el índice del corchete de cierre que corresponde al de apertura
     * en la posición openIdx.
     */
    private static int findMatchingBracket(String s, int openIdx) throws IOException {
        int depth = 0;
        for (int i = openIdx; i < s.length(); i++) {
            if (s.charAt(i) == '[') depth++;
            else if (s.charAt(i) == ']') {
                depth--;
                if (depth == 0) return i;
            }
        }
        throw new IOException("Corchete de cierre no encontrado");
    }

    private static LMSigParameters parseLMSigParameters(String name) throws IOException {
        return switch (name.toLowerCase().trim()) {
            case "lms_sha256_n32_h5" -> LMSigParameters.lms_sha256_n32_h5;
            case "lms_sha256_n32_h10" -> LMSigParameters.lms_sha256_n32_h10;
            case "lms_sha256_n32_h15" -> LMSigParameters.lms_sha256_n32_h15;
            case "lms_sha256_n32_h20" -> LMSigParameters.lms_sha256_n32_h20;
            case "lms_sha256_n24_h5" -> LMSigParameters.lms_sha256_n24_h5;
            case "lms_sha256_n24_h10" -> LMSigParameters.lms_sha256_n24_h10;
            case "lms_sha256_n24_h15" -> LMSigParameters.lms_sha256_n24_h15;
            case "lms_sha256_n24_h20" -> LMSigParameters.lms_sha256_n24_h20;
            default -> throw new IOException("Parámetro LMS desconocido: '" + name + "'");
        };
    }

    private static LMOtsParameters parseLMOtsParameters(String name) throws IOException {
        return switch (name.toLowerCase().trim()) {
            case "sha256_n32_w1" -> LMOtsParameters.sha256_n32_w1;
            case "sha256_n32_w2" -> LMOtsParameters.sha256_n32_w2;
            case "sha256_n32_w4" -> LMOtsParameters.sha256_n32_w4;
            case "sha256_n32_w8" -> LMOtsParameters.sha256_n32_w8;
            case "sha256_n24_w1" -> LMOtsParameters.sha256_n24_w1;
            case "sha256_n24_w2" -> LMOtsParameters.sha256_n24_w2;
            case "sha256_n24_w4" -> LMOtsParameters.sha256_n24_w4;
            case "sha256_n24_w8" -> LMOtsParameters.sha256_n24_w8;
            default -> throw new IOException("Parámetro LM-OTS desconocido: '" + name + "'");
        };
    }
}