package de.usd.cstchef.operations.vietjetair;

import burp.api.montoya.core.ByteArray;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ThreadLocalRandom;

@OperationInfos(name = "API - RequestId Generator", category = OperationCategory.VIETJETAIR, description = "Generate new RequestId")
public class ReqIdGenerator extends Operation {

    public static String generateRequestId() {
        String CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        int PREFIX_LEN = 13;
        ThreadLocalRandom rnd = ThreadLocalRandom.current();
        StringBuilder sb = new StringBuilder(PREFIX_LEN + 1 + 13);
        for (int i = 0; i < PREFIX_LEN; i++) {
            sb.append(CHARS.charAt(rnd.nextInt(CHARS.length())));
        }
        sb.append('-').append(System.currentTimeMillis());
        return sb.toString();
    }

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        String body = new String(input.getBytes(), StandardCharsets.UTF_8);
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonObject = mapper.readTree(body);
        ((ObjectNode)jsonObject).put("requestId", generateRequestId());
        return factory.createByteArray(mapper.writeValueAsString(jsonObject).getBytes());
    }

}