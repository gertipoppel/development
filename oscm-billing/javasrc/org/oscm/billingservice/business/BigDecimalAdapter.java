/*******************************************************************************
 *  Copyright FUJITSU LIMITED 2016 
 *******************************************************************************/

package org.oscm.billingservice.business;

import java.math.BigDecimal;

import javax.xml.bind.annotation.adapters.XmlAdapter;

public class BigDecimalAdapter extends XmlAdapter<String, BigDecimal> {

    public BigDecimal unmarshal(String value) {
        return (org.oscm.billingservice.business.BigDecimalJaxbCustomBinder
                .parseBigDecimal(value));
    }

    public String marshal(BigDecimal value) {
        return (org.oscm.billingservice.business.BigDecimalJaxbCustomBinder
                .printBigDecimal(value));
    }
}
