package de.usd.cstchef.operations.vietjetair;

import javax.swing.*;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.conditional.ConditionalOperation;

import java.util.regex.Pattern;

@OperationInfos(name = "API - Is From Repeater Tab", category = OperationCategory.VIETJETAIR, description = "Is request from repeater tab")
public class IsRequestFromRepeater extends ConditionalOperation {

    private JCheckBox invert;
    private JComboBox<String> operationBox;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        Boolean condition = false;

        HttpRequest inputRequest = factory.createHttpRequest(input);
        String customHeader = inputRequest.headerValue("X-Repeater");
        if (customHeader != null && customHeader.length() != 0 ) {
            condition = true;
        }

        if( condition ^ this.invert.isSelected()) {
            this.setOperationSkip();
            this.setLaneSkip();
        } else {
            this.resetSkips();
        }

        ByteArray body = factory.getHttpRequestBody(input);
        return body;
    }

    @Override
    public void createUI() {
        super.createUI();

        this.invert = new JCheckBox();
        this.addUIElement("Invert Match", this.invert);
    }

}
