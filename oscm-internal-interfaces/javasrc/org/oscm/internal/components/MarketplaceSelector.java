/*******************************************************************************
 *  Copyright FUJITSU LIMITED 2016 
 *******************************************************************************/

package org.oscm.internal.components;

import java.util.List;

import javax.ejb.Local;

/**
 * Local interface of the marketplace selector bean
 * 
 */
@Local
public interface MarketplaceSelector {

    public List<POMarketplace> getMarketplaces();

    public List<POMarketplace> getMarketplacesForPublishing();

}
