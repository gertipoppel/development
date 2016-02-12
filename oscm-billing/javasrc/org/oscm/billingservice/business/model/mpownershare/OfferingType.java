/*******************************************************************************
 *  Copyright FUJITSU LIMITED 2016 
 *******************************************************************************/

package org.oscm.billingservice.business.model.mpownershare;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;

@XmlType(name = "OfferingType")
@XmlEnum
public enum OfferingType {

    DIRECT,

    BROKER,

    RESELLER;

    public String value() {
        return name();
    }

    public static OfferingType fromValue(String v) {
        return valueOf(v);
    }

}
