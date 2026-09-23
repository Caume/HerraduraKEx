package herradurakex;

/**
 * One of BITARRAY.md §5's eight error codes, plus the operation that raised it
 * (TODO #314 pass 5).
 *
 * The SET is what has to match across the four ports, not the mechanism: C
 * returns a {@code BaStatus}, Go returns an {@code error}, Python and Java
 * raise.  A conformance vector pins the CODE, which is what makes "failed for
 * the right reason" distinguishable from "failed".
 *
 * Unchecked on purpose.  At the protocol layer a mixed width or an invalid
 * width is a BUG, not an input to be handled — the same position C takes with
 * {@code BA_FAIL} and Go with a panic — and making it checked would put a
 * {@code throws} clause on every signature in the port to describe a condition
 * that must never occur.
 */
public final class BaException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /** BITARRAY.md §5 — a closed set, spelled identically in every port. */
    public static final String E_WIDTH       = "E_WIDTH";
    public static final String E_MIXED_WIDTH = "E_MIXED_WIDTH";
    public static final String E_LENGTH      = "E_LENGTH";
    public static final String E_RANGE       = "E_RANGE";
    public static final String E_LOSSY       = "E_LOSSY";
    public static final String E_HEXDIGIT    = "E_HEXDIGIT";
    public static final String E_NO_POLY     = "E_NO_POLY";
    public static final String E_ENTROPY     = "E_ENTROPY";

    private final String code;
    private final String op;

    public BaException(String code, String op) {
        super(code + " in " + op);
        this.code = code;
        this.op = op;
    }

    /** The BITARRAY.md §5 code, for a consumer comparing against a vector. */
    public String code() { return code; }

    /** The operation that raised it. */
    public String op() { return op; }
}
