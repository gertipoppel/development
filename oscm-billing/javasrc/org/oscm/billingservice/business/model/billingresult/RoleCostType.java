/*******************************************************************************
 *  Copyright FUJITSU LIMITED 2016 
 *******************************************************************************/

//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vJAXB 2.1.10 in JDK 6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2013.03.05 at 01:29:11 PM CET 
//

package org.oscm.billingservice.business.model.billingresult;

import java.math.BigDecimal;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import org.oscm.billingservice.business.BigDecimalAdapter;

/**
 * Costs for one user role.
 * 
 * <p>
 * Java class for RoleCostType complex type.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within
 * this class.
 * 
 * <pre>
 * &lt;complexType name="RoleCostType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;attribute name="id" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="basePrice" use="required" type="{http://www.w3.org/2001/XMLSchema}decimal" />
 *       &lt;attribute name="factor" use="required" type="{http://www.w3.org/2001/XMLSchema}decimal" />
 *       &lt;attribute name="price" use="required" type="{}NormalizedCosts" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RoleCostType")
public class RoleCostType {

    @XmlAttribute(required = true)
    protected String id;

    @XmlAttribute(required = true)
    @XmlJavaTypeAdapter(BigDecimalAdapter.class)
    protected BigDecimal basePrice;

    @XmlAttribute(required = true)
    protected BigDecimal factor;

    @XmlAttribute(required = true)
    @XmlJavaTypeAdapter(BigDecimalAdapter.class)
    protected BigDecimal price;

    /**
     * Gets the value of the id property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the value of the id property.
     * 
     * @param value
     *            allowed object is {@link String }
     * 
     */
    public void setId(String value) {
        this.id = value;
    }

    /**
     * Gets the value of the basePrice property.
     * 
     * @return possible object is {@link BigDecimal }
     * 
     */
    public BigDecimal getBasePrice() {
        return basePrice;
    }

    /**
     * Sets the value of the basePrice property.
     * 
     * @param value
     *            allowed object is {@link BigDecimal }
     * 
     */
    public void setBasePrice(BigDecimal value) {
        this.basePrice = value;
    }

    /**
     * Gets the value of the factor property.
     * 
     * @return possible object is {@link BigDecimal }
     * 
     */
    public BigDecimal getFactor() {
        return factor;
    }

    /**
     * Sets the value of the factor property.
     * 
     * @param value
     *            allowed object is {@link BigDecimal }
     * 
     */
    public void setFactor(BigDecimal value) {
        this.factor = value;
    }

    /**
     * Gets the value of the price property.
     * 
     * @return possible object is {@link BigDecimal }
     * 
     */
    public BigDecimal getPrice() {
        return price;
    }

    /**
     * Sets the value of the price property.
     * 
     * @param value
     *            allowed object is {@link BigDecimal }
     * 
     */
    public void setPrice(BigDecimal value) {
        this.price = value;
    }

}
