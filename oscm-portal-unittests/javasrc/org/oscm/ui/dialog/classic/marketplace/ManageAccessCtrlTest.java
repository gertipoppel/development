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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Matchers;
import org.oscm.internal.intf.MarketplaceService;
import org.oscm.internal.marketplace.POOrganization;
import org.oscm.internal.types.exception.NonUniqueBusinessKeyException;
import org.oscm.internal.types.exception.ObjectNotFoundException;
import org.oscm.internal.types.exception.OperationNotPermittedException;
import org.oscm.internal.vo.VOMarketplace;
import org.oscm.internal.vo.VOOrganization;
import org.oscm.ui.beans.BaseBean;
import org.oscm.ui.stubs.FacesContextStub;

public class ManageAccessCtrlTest {

    private ManageAccessCtrl ctrl;
    private ManageAccessModel model;
    private MarketplaceService marketplaceService;

    private static final String MARKETPLACE_ID = "marketplace1";
    private static final String MARKETPLACE_NAME = "marketplace1Name";

    @Before
    public void setup() {

        new FacesContextStub(Locale.ENGLISH);

        marketplaceService = mock(MarketplaceService.class);

        ctrl = spy(new ManageAccessCtrl());
        model = new ManageAccessModel();

        ctrl.setModel(model);
        ctrl.setMarketplaceService(marketplaceService);
    }

    @Test
    public void testInitializedMarketplaces() {

        // given
        doReturn(getSampleMarketplaces()).when(marketplaceService)
                .getMarketplacesOwned();

        // when
        ctrl.initialize();

        // then
        verify(marketplaceService, times(1)).getMarketplacesOwned();
        assertEquals(2, model.getSelectableMarketplaces().size());
    }

    @Test
    public void testSelectedMarketplace() throws Exception {

        // given
        model.setSelectedMarketplaceId(MARKETPLACE_ID);
        doReturn(createSampleMarketplace(MARKETPLACE_NAME, MARKETPLACE_ID))
                .when(marketplaceService).getMarketplaceById(MARKETPLACE_ID);

        // when
        ctrl.marketplaceChanged();

        // then
        verify(marketplaceService, times(1)).getMarketplaceById(MARKETPLACE_ID);
    }

    @Test
    public void testNotSelectedMarketplace() throws Exception {

        // given
        model.setSelectedMarketplaceId(null);

        // when
        ctrl.marketplaceChanged();

        // then
        verify(marketplaceService, times(0)).getMarketplaceById(MARKETPLACE_ID);
        assertEquals(false, model.isSelectedMarketplaceRestricted());
    }

    @Test
    public void testAccessChange() throws Exception{
        // given
        ctrl.getModel().setSelectedMarketplaceId(MARKETPLACE_ID);
        ctrl.getModel().setSelectedMarketplaceRestricted(true);

        // when
        ctrl.accessChanged();

        // then
        verify(marketplaceService, times(1))
                .getAllOrganizations(MARKETPLACE_ID);
    }

    @Test
    public void testSave_organizationsLists() throws Exception {

        // given
        setupValuesForSaveAction(true);
        doNothing().when(marketplaceService).closeMarketplace(anyString(),
                Matchers.anySetOf(Long.class),Matchers.anySetOf(Long.class),Matchers.anySetOf(Long.class));
        // when
        String result = ctrl.save();

        // then
        assertEquals(0, model.getAuthorizedOrganizations().size());
        assertEquals(0, model.getUnauthorizedOrganizations().size());
        assertEquals(BaseBean.OUTCOME_SUCCESS, result);
    }

    @Test
    public void testSave_closeMarketplace() throws Exception {

        // given
        setupValuesForSaveAction(true);
        doNothing().when(marketplaceService).closeMarketplace(anyString(),
                Matchers.anySetOf(Long.class),
                Matchers.anySetOf(Long.class),Matchers.anySetOf(Long.class));
        // when
        String result = ctrl.save();

        // then
        verify(marketplaceService, times(1)).closeMarketplace(MARKETPLACE_ID,
                model.getAuthorizedOrganizations(),
                model.getUnauthorizedOrganizations(), model.getOrganizationsWithSubscriptionsToSuspend());
        assertEquals(BaseBean.OUTCOME_SUCCESS, result);
    }

    @Test
    public void testSave_openMarketplace()
            throws OperationNotPermittedException, ObjectNotFoundException,
            NonUniqueBusinessKeyException {

        // given
        setupValuesForSaveAction(false);
        doNothing().when(marketplaceService).openMarketplace(anyString());
        // when
        String result = ctrl.save();

        // then
        verify(marketplaceService, times(1)).openMarketplace(MARKETPLACE_ID);
        assertEquals(BaseBean.OUTCOME_SUCCESS, result);
    }
    
    @Test
    public void testChangeOrganizationAccessOrgNotSelected(){
        
        //given
        model.setChangedKey(10005L);
        model.setChangedSelection(false);
        model.setChangedHasSubscriptions(true);
        model.getAccessesSelected().put(10005L, true);
        model.getOrganizationsWithSubscriptionsToSuspend().clear();
        
        //when
        ctrl.changeOrganizationAccess();
        
        //then
        assertFalse(model.getOrganizationsWithSubscriptionsToSuspend().isEmpty());
        assertTrue(model.isShowSubscriptionSuspendingWarning());
    }
    
    @Test
    public void testChangeOrganizationAccessOrgSelected(){
        
        //given
        model.setChangedKey(10005L);
        model.setChangedSelection(true);
        model.setChangedHasSubscriptions(true);
        model.getAccessesSelected().put(10005L, true);
        model.getOrganizationsWithSubscriptionsToSuspend().clear();
        
        //when
        ctrl.changeOrganizationAccess();
        
        //then
        assertTrue(model.getOrganizationsWithSubscriptionsToSuspend().isEmpty());
        assertFalse(model.isShowSubscriptionSuspendingWarning());
    }

    private void setupValuesForSaveAction(boolean restrictMarketplace)
            throws OperationNotPermittedException, ObjectNotFoundException,
            NonUniqueBusinessKeyException {
        model.setSelectedMarketplaceId(MARKETPLACE_ID);
        model.setOrganizations(preparePOOrganizationsList());
        model.setSelectedMarketplaceRestricted(restrictMarketplace);
        
        VOMarketplace marketplace = createSampleMarketplace(MARKETPLACE_NAME, MARKETPLACE_ID);
        marketplace.setRestricted(restrictMarketplace);
        
        doNothing().when(ctrl).addMessage(any(String.class));
    }

    private List<VOMarketplace> getSampleMarketplaces() {

        VOMarketplace marketplace1 = createSampleMarketplace("TestMarketplace1",
                "c34567fg");
        VOMarketplace marketplace2 = createSampleMarketplace("TestMarketplace2",
                "45tf7s20");

        List<VOMarketplace> marketplaces = new ArrayList<>();
        marketplaces.add(marketplace1);
        marketplaces.add(marketplace2);

        return marketplaces;
    }

    private VOMarketplace createSampleMarketplace(String name, String id) {

        VOMarketplace marketplace = new VOMarketplace();
        marketplace.setMarketplaceId(id);
        marketplace.setName(name);

        return marketplace;
    }

    private List<POOrganization> preparePOOrganizationsList() {
        List<POOrganization> organizations = new ArrayList<>();
        organizations.add(preparePOOrganization(1L, "org1", true));
        organizations.add(preparePOOrganization(2L, "org2", false));
        model.getAccessesStored().put(1L, new Boolean(false));
        model.getAccessesStored().put(2L, new Boolean(true));
        return organizations;
    }

    private POOrganization preparePOOrganization(long key,
            String organizationId, boolean selected) {
        POOrganization poOrganization = new POOrganization();
        poOrganization.setOrganizationId(organizationId);
        poOrganization.setKey(key);
        poOrganization.setName(organizationId + "Name");
        poOrganization.setSelected(selected);
        return poOrganization;
    }
}
