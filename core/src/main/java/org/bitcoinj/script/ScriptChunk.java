/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.script;

import org.bitcoinj.core.Utils;
import com.google.common.base.Objects;
import com.google.common.primitives.Bytes;

import javax.annotation.Nullable;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;
import static org.bitcoinj.script.ScriptOpCodes.*;

/**
 * A script element that is either a data push (signature, pubkey, etc) or a non-push (logic, numeric, etc) operation.
 */
public class ScriptChunk {
    private final int opcode;
    @Nullable
    private final byte[] data;
    private int startLocationInProgram;

    private static final byte[] OP_0_BYTE_ARRAY = new byte[]{};
    private static final byte[] OP_1NEGATE_BYTE_ARRAY = Utils.reverseBytes(Utils.encodeMPI(BigInteger.ONE.negate(), false));

    public ScriptChunk(int opcode, byte[] data) {
        this(opcode, data, -1);
        if (isPushData() && (opcode == OP_0 || opcode == OP_1NEGATE || (opcode >= OP_1 && opcode <= OP_16)))
            checkArgument(data == null, "Data must be null for opcode "+opcode);
    }

    public ScriptChunk(int opcode, byte[] data, int startLocationInProgram) {
        this.opcode = opcode;
        this.data = Arrays.copyOf(data, data.length);
        this.startLocationInProgram = startLocationInProgram;
    }

    /**
     * Operation to be executed. Opcodes are defined in {@link ScriptOpCodes}.
     * @return the opcode for this operation.
     */
    public int getOpcode() {
        return opcode;
    }

    /**
     * For push operations, this is the vector to be pushed on the stack. For {@link ScriptOpCodes#OP_0}, the vector is
     * empty. Null for non-push operations.
     * <p>The data is represented in little-endian.<p/>
     * @return the data for push operations, null otherwise.
     * @see ScriptChunk#isPushData()
     */
    public byte[] getData() {
        if (opcode == OP_0)
            return OP_0_BYTE_ARRAY;
        if (opcode == OP_1NEGATE)
            return OP_1NEGATE_BYTE_ARRAY;
        if (opcode >= OP_1 && opcode <= OP_16)
            return new byte[]{(byte)(opcode + 1 - OP_1)};
        return data;
    }

    /**
     * Decode the data vector for push operations.
     * <p>Same of <code>Utils.decodeMPI(Utils.reverseBytes(getData()), false);</code></p>
     * @return the value obtained decoding getData().
     * @see Utils#decodeMPI(byte[], boolean)
     * @see Utils#reverseBytes(byte[])
     */
    public BigInteger getDataValue() {
        checkState(isPushData());
        if (opcode == OP_0)
            return BigInteger.ZERO;
        if (opcode == OP_1NEGATE)
            return BigInteger.ONE.negate();
        if (opcode >= OP_1 && opcode <= OP_16)
            return BigInteger.valueOf(opcode + 1 - OP_1);
        return Utils.decodeMPI(Utils.reverseBytes(data), false);
    }

    public boolean equalsOpCode(int opcode) {
        return opcode == this.opcode;
    }

    /**
     * If this chunk is a single byte of non-pushdata content (could be OP_RESERVED or some invalid Opcode)
     */
    public boolean isOpCode() {
        return opcode > OP_PUSHDATA4;
    }

    /**
     * Returns true if this chunk is pushdata content, including the single-byte pushdatas.
     */
    public boolean isPushData() {
        return opcode <= OP_16;
    }

    public int getStartLocationInProgram() {
        checkState(startLocationInProgram >= 0);
        return startLocationInProgram;
    }

    /** If this chunk is an OP_N opcode returns the equivalent integer value. */
    public int decodeOpN() {
        checkState(isOpCode());
        return Script.decodeFromOpN(opcode);
    }

    /**
     * Called on a pushdata chunk, returns true if it uses the smallest possible way (according to BIP62) to push the data.
     */
    public boolean isShortestPossiblePushData() {
        checkState(isPushData());
        if (data == null)
            return true;   // OP_N
        if (data.length == 0)
            return opcode == OP_0;
        if (data.length == 1) {
            byte b = data[0];
            if (b >= 0x01 && b <= 0x10)
                return opcode == OP_1 + b - 1;
            if ((b & 0xFF) == 0x81)
                return opcode == OP_1NEGATE;
        }
        if (data.length < OP_PUSHDATA1)
            return opcode == data.length;
        if (data.length < 256)
            return opcode == OP_PUSHDATA1;
        if (data.length < 65536)
            return opcode == OP_PUSHDATA2;

        // can never be used, but implemented for completeness
        return opcode == OP_PUSHDATA4;
    }

    public byte[] toByteArray() {
        if (isOpCode()) {
            checkState(data == null);
            return new byte[]{ (byte) opcode };
        } else if (data != null) {
            ArrayList<Byte> res = new ArrayList<>();
            if (opcode < OP_PUSHDATA1) {
                checkState(data.length == opcode);
                res.add((byte) opcode);
            } else if (opcode == OP_PUSHDATA1) {
                checkState(data.length <= 0xFF);
                res.add((byte) OP_PUSHDATA1);
                res.add((byte) data.length);
            } else if (opcode == OP_PUSHDATA2) {
                checkState(data.length <= 0xFFFF);
                res.add((byte) OP_PUSHDATA2);
                res.add((byte) (0xFF & data.length));
                res.add((byte) (0xFF & (data.length >> 8)));
            } else if (opcode == OP_PUSHDATA4) {
                checkState(data.length <= Script.MAX_SCRIPT_ELEMENT_SIZE);
                res.add((byte) OP_PUSHDATA4);
                res.add((byte) (0xFF & data.length));
                res.add((byte) (0xFF & (data.length >> 8)));
                res.add((byte) (0xFF & (data.length >> 16)));
                res.add((byte) (0xFF & (data.length >> 24)));
            } else {
                throw new RuntimeException("Unimplemented");
            }
            return Bytes.concat(Bytes.toArray(res), data);
        } else {
            return new byte[] { (byte) opcode }; // smallNum
        }
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        if (isOpCode()) {
            buf.append(getOpCodeName(opcode));
        } else if (data != null) {
            // Data chunk
            buf.append(getPushDataName(opcode)).append("[").append(Utils.HEX.encode(data)).append("]");
        } else {
            // Small num
            buf.append(Script.decodeFromOpN(opcode));
        }
        return buf.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ScriptChunk other = (ScriptChunk) o;
        return opcode == other.opcode && startLocationInProgram == other.startLocationInProgram
            && Arrays.equals(data, other.data);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(opcode, startLocationInProgram, Arrays.hashCode(data));
    }
}
