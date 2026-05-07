package es.uma.nicslab.hbs.model;

public class ThresholdSignature {

    private final byte[] R; // Randomizer reconstruido — n bytes
    private final byte[][] PATH; // Camino Merkle reconstruido — h nodos de n bytes
    private final byte[] Z; // Firma Winternitz reconstruida — p*n bytes

    public ThresholdSignature(byte[] R, byte[][] PATH, byte[] Z) {
        this.R = R != null ? R.clone() : null;
        if (PATH != null) {
            this.PATH = new byte[PATH.length][];
            for (int i = 0; i < PATH.length; i++) {
                this.PATH[i] = PATH[i] != null ? PATH[i].clone() : null;
            }
        } else {
            this.PATH = null;
        }
        this.Z = Z != null ? Z.clone() : null;
    }

    public byte[] getR() {
        return R != null ? R.clone() : null;
    }

    public byte[][] getPATH() {
        if (PATH == null) return null;
        byte[][] copy = new byte[PATH.length][];
        for (int i = 0; i < PATH.length; i++) {
            copy[i] = PATH[i] != null ? PATH[i].clone() : null;
        }
        return copy;
    }

    public byte[] getZ() {
        return Z != null ? Z.clone() : null;
    }

}