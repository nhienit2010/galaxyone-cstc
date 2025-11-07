package de.usd.cstchef.operations.vietjetair;

import javax.swing.JComboBox;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.conditional.ConditionalOperation;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@OperationInfos(name = "API - Skip Out-of-Scope Requests All In One", category = OperationCategory.VIETJETAIR, description = "Skip Out-of-Scope Request VJAPI")
public class SkipOosRequest extends ConditionalOperation {

    private JComboBox<String> operationBox;

    public static boolean checkWhiteListHost(String[] array, String value) {
        for (String s : array) {
            if (s.equals(value)) {
                return true;
            }
        }
        return false;
    }

    public static boolean checkIgnorePath(String[] array, String value) {
        for (String s : array) {
            if (value.contains(s)) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        Boolean condition = true;

        // Parse HTTP Request
        HttpRequest inputRequest = factory.createHttpRequest(input);
        // Accept methods
        Pattern p = Pattern.compile("^(POST|PUT|PATCH)$");
        // Get Host in scope
        String[] uriScope = this.expr.getText().split(",");
        // Get URL path
        String urlPath = inputRequest.url().split("\\?")[0];
        String[] ignorePath = {"/user/api/v1/"};

        if (p.matcher(inputRequest.method().toString()).find()) {
            if (checkWhiteListHost(uriScope, inputRequest.headerValue("Host"))) {
                if (!checkIgnorePath(ignorePath, urlPath)) {
                    condition = false;
                }
            }
        }

        if( condition ) {
            this.setOperationSkip();
            this.setLaneSkip();
        } else {
            this.resetSkips();
        }

        return input;
    }

    @Override
    public void createUI() {
        super.createUI();
    }

}
