//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.3.2 
// See <a href="https://javaee.github.io/jaxb-v2/">https://javaee.github.io/jaxb-v2/</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2020.04.01 at 10:04:03 PM CEST 
//


package org.opentelecoms.gsm0348.api.model;

import java.util.Objects;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for SPI complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SPI"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;all&gt;
 *         &lt;element name="CommandSPI" type="{org.opentelecoms.gsm0348}CommandSPI"/&gt;
 *         &lt;element name="ResponseSPI" type="{org.opentelecoms.gsm0348}ResponseSPI"/&gt;
 *       &lt;/all&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SPI", propOrder = {

})
public class SPI {

    @XmlElement(name = "CommandSPI", required = true)
    protected CommandSPI commandSPI;
    @XmlElement(name = "ResponseSPI", required = true)
    protected ResponseSPI responseSPI;

    /**
     * Gets the value of the commandSPI property.
     * 
     * @return
     *     possible object is
     *     {@link CommandSPI }
     *     
     */
    public CommandSPI getCommandSPI() {
        return commandSPI;
    }

    /**
     * Sets the value of the commandSPI property.
     * 
     * @param value
     *     allowed object is
     *     {@link CommandSPI }
     *     
     */
    public void setCommandSPI(CommandSPI value) {
        this.commandSPI = value;
    }

    /**
     * Gets the value of the responseSPI property.
     * 
     * @return
     *     possible object is
     *     {@link ResponseSPI }
     *     
     */
    public ResponseSPI getResponseSPI() {
        return responseSPI;
    }

    /**
     * Sets the value of the responseSPI property.
     * 
     * @param value
     *     allowed object is
     *     {@link ResponseSPI }
     *     
     */
    public void setResponseSPI(ResponseSPI value) {
        this.responseSPI = value;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SPI)) {
            return false;
        }
        final SPI spi = (SPI) o;
        return Objects.equals(commandSPI, spi.commandSPI) &&
            Objects.equals(responseSPI, spi.responseSPI);
    }

    @Override
    public int hashCode() {
        return Objects.hash(commandSPI, responseSPI);
    }

    @Override
    public String toString()
    {
        StringBuilder builder = new StringBuilder();
        builder.append("SPI [commandSPI=");
        builder.append(commandSPI);
        builder.append(", responseSPI=");
        builder.append(responseSPI);
        builder.append("]");
        return builder.toString();
    }
}