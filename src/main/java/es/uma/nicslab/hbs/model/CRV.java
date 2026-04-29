package es.uma.nicslab.hbs.model;

import org.bouncycastle.util.encoders.Hex;

public class CRV {

    private final byte[] R; // Randomizer
    private final byte[] CHK; // Key-dependent check value for R
    private final byte[][] PATH; // Camino de autenticación
    private final byte[][][] SK; // Cadena de hashes

    public CRV(byte[] R, byte[] CHK, byte[][] PATH, byte[][][] SK) {
        this.R = R != null ? R.clone() : null;
        this.CHK = CHK != null ? CHK.clone() : null;
        if (PATH != null) {
            this.PATH = new byte[PATH.length][];
            for (int i = 0; i < PATH.length; i++) {
                this.PATH[i] = PATH[i] != null ? PATH[i].clone() : null;
            }
        } else {
            this.PATH = null;
        }
        if (SK != null) {
            this.SK = new byte[SK.length][][];
            for (int i = 0; i < SK.length; i++) {
                this.SK[i] = new byte[SK[i].length][];
                for (int j = 0; j < SK[i].length; j++) {
                    this.SK[i][j] = SK[i][j] != null ? SK[i][j].clone() : null;
                }
            }
        } else {
            this.SK = null;
        }
    }

    public byte[] getR() {
        return R != null ? R.clone() : null;
    }

    public byte[] getCHK() {
        return CHK != null ? CHK.clone() : null;
    }

    public byte[][] getPATH() {
        if (PATH == null) return null;
        byte[][] copy = new byte[PATH.length][];
        for (int i = 0; i < PATH.length; i++) {
            copy[i] = PATH[i] != null ? PATH[i].clone() : null;
        }
        return copy;
    }

    public byte[][][] getSK() {
        if (SK == null) return null;
        byte[][][] copy = new byte[SK.length][][];
        for (int i = 0; i < SK.length; i++) {
            copy[i] = new byte[SK[i].length][];
            for (int j = 0; j < SK[i].length; j++) {
                copy[i][j] = SK[i][j] != null ? SK[i][j].clone() : null;
            }
        }
        return copy;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("CRV {\n");

        // R — byte[]
        sb.append("  R:    ").append(R != null ? Hex.toHexString(R) : "null").append("\n");

        // CHK — byte[]
        sb.append("  CHK:  ").append(CHK != null ? Hex.toHexString(CHK) : "null").append("\n");

        // PATH — byte[]
        sb.append("  PATH: [\n");
        if (PATH != null) {
            for (int i = 0; i < PATH.length; i++) {
                sb.append("    Node ").append(i).append(": ")
                        .append(PATH[i] != null ? Hex.toHexString(PATH[i]) : "null")
                        .append("\n");
            }
        } else {
            sb.append("    null\n");
        }
        sb.append("  ]\n");

        // SK — byte[][][]
        sb.append("  SK: [\n");
        if (SK != null) {
            for (int i = 0; i < SK.length; i++) {
                sb.append("    Chain ").append(i).append(": [");
                for (int j = 0; j < SK[i].length; j++) {
                    sb.append(SK[i][j] != null ? Hex.toHexString(SK[i][j]) : "null");
                    if (j < SK[i].length - 1) sb.append(", ");
                }
                sb.append("]\n");
            }
        } else {
            sb.append("    null\n");
        }
        sb.append("  ]\n");

        sb.append("}");
        return sb.toString();
    }

}
