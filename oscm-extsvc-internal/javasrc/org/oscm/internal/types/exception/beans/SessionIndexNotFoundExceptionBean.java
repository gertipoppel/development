/*******************************************************************************
 *
 *  Copyright FUJITSU LIMITED 2016                                             
 *
 *  Creation Date: Jun 14, 2013                                                      
 *
 *******************************************************************************/

package org.oscm.internal.types.exception.beans;

import org.oscm.internal.types.exception.SessionIndexNotFoundException.ReasonEnum;

/**
 * @author dchojnacki
 *
 */
public class SessionIndexNotFoundExceptionBean extends ApplicationExceptionBean {

    private static final long serialVersionUID = 5936767140334626354L;
    private ReasonEnum reason;

    /**
     * Default constructor.
     */
    public SessionIndexNotFoundExceptionBean() {
        super();
    }

    /**
     * Instantiates a <code>SessionNotFoundExceptionBean</code> based on the
     * specified <code>ApplicationExceptionBean</code> and sets the given
     * reason.
     *
     * @param sup
     *            the <code>ApplicationExceptionBean</code> to use as the base
     * @param reason
     *            the reason for the exception
     */
    public SessionIndexNotFoundExceptionBean(ApplicationExceptionBean sup,
                                             ReasonEnum reason) {
        super(sup);
        setReason(reason);
    }

    /**
     * Returns the reason for the exception.
     *
     * @return the reason
     */
    public ReasonEnum getReason() {
        return reason;
    }

    /**
     * Sets the reason for the exception.
     *
     * @param reason
     *            the reason
     */
    public void setReason(ReasonEnum reason) {
        this.reason = reason;
    }

}