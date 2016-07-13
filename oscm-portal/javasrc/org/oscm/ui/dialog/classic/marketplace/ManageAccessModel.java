/*******************************************************************************
 *                                                                              
 *  Copyright FUJITSU LIMITED 2016                                             
 *                                                                              
 *  Author: kowalczyka                                                      
 *                                                                              
 *  Creation Date: 18.05.2016                                                      
 *                                                                              
 *******************************************************************************/

package org.oscm.ui.dialog.classic.marketplace;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.model.SelectItem;

import org.oscm.internal.marketplace.POOrganization;

@ManagedBean
@ViewScoped
public class ManageAccessModel {

    private List<SelectItem> selectableMarketplaces;

    private String selectedMarketplaceId;

    private boolean selectedMarketplaceRestricted;
    
    private boolean allOrganizationsSelected;

    private List<POOrganization> organizations;

    private Map<Long, Boolean> accessesStored = new HashMap<>();

    private Map<Long, Boolean> accessesSelected = new HashMap<>();

    private Set<Long> authorizedOrganizations = new HashSet<>();;

    private Set<Long> unauthorizedOrganizations = new HashSet<>();

    private Set<Long> organizationsWithSubscriptionsToSuspend = new HashSet<>();

    private boolean showSubscriptionSuspendingWarning;

    private boolean showOpeningRestrictedMplWarning;

    private long changedKey;
    
    private boolean changedSelection;
    
    private boolean changedHasSubscriptions;
    
    private String allSelectedOrganizations;
    
    public List<SelectItem> getSelectableMarketplaces() {
        return selectableMarketplaces;
    }

    public void setSelectableMarketplaces(
            List<SelectItem> selectableMarketplaces) {
        this.selectableMarketplaces = selectableMarketplaces;
    }

    public String getSelectedMarketplaceId() {
        return selectedMarketplaceId;
    }

    public void setSelectedMarketplaceId(String selectedMarketplaceId) {
        this.selectedMarketplaceId = selectedMarketplaceId;
    }

    public boolean isSelectedMarketplaceRestricted() {
        return selectedMarketplaceRestricted;
    }

    public void setSelectedMarketplaceRestricted(
            boolean selectedMarketplaceRestricted) {
        this.selectedMarketplaceRestricted = selectedMarketplaceRestricted;
    }
    
    public boolean isAllOrganizationsSelected() {
        return allOrganizationsSelected;
    }

    public void setAllOrganizationsSelected(boolean allOrganizationsSelected) {
        this.allOrganizationsSelected = allOrganizationsSelected;
    }

    public List<POOrganization> getOrganizations() {
        return organizations;
    }

    public void setOrganizations(List<POOrganization> organizations) {
        this.organizations = organizations;
    }

    public Map<Long, Boolean> getAccessesStored() {
        return accessesStored;
    }

    public void setAccessesStored(Map<Long, Boolean> accessesStored) {
        this.accessesStored = accessesStored;
    }

    public Map<Long, Boolean> getAccessesSelected() {
        return accessesSelected;
    }

    public void setAccessesSelected(Map<Long, Boolean> accessesSelected) {
        this.accessesSelected = accessesSelected;
    }

    public Set<Long> getAuthorizedOrganizations() {
        return authorizedOrganizations;
    }

    public void setAuthorizedOrganizations(Set<Long> authorizedOrganizations) {
        this.authorizedOrganizations = authorizedOrganizations;
    }

    public Set<Long> getUnauthorizedOrganizations() {
        return unauthorizedOrganizations;
    }

    public void setUnauthorizedOrganizations(
            Set<Long> unauthorizedOrganizations) {
        this.unauthorizedOrganizations = unauthorizedOrganizations;
    }

    public Set<Long> getOrganizationsWithSubscriptionsToSuspend() {
        return organizationsWithSubscriptionsToSuspend;
    }

    public void setOrganizationsWithSubscriptionsToSuspend(
            Set<Long> organizationsWithSubscriptionsToSuspend) {
        this.organizationsWithSubscriptionsToSuspend = organizationsWithSubscriptionsToSuspend;
    }

    public boolean isShowSubscriptionSuspendingWarning() {
        return showSubscriptionSuspendingWarning;
    }

    public void setShowSubscriptionSuspendingWarning(
            boolean showSubscriptionSuspendingWarning) {
        this.showSubscriptionSuspendingWarning = showSubscriptionSuspendingWarning;
    }

    public boolean isShowOpeningRestrictedMplWarning() {
        return showOpeningRestrictedMplWarning;
    }

    public void setShowOpeningRestrictedMplWarning(
            boolean showOpeningRestrictedMplWarning) {
        this.showOpeningRestrictedMplWarning = showOpeningRestrictedMplWarning;
    }

    public long getChangedKey() {
        return changedKey;
    }

    public void setChangedKey(long changedKey) {
        this.changedKey = changedKey;
    }

    public boolean isChangedSelection() {
        return changedSelection;
    }

    public void setChangedSelection(boolean changedSelection) {
        this.changedSelection = changedSelection;
    }

    public boolean isChangedHasSubscriptions() {
        return changedHasSubscriptions;
    }

    public void setChangedHasSubscriptions(boolean changedHasSubscriptions) {
        this.changedHasSubscriptions = changedHasSubscriptions;
    }

    public String getAllSelectedOrganizations() {
        return allSelectedOrganizations;
    }

    public void setAllSelectedOrganizations(String allSelectedOrganizations) {
        this.allSelectedOrganizations = allSelectedOrganizations;
    }
}
