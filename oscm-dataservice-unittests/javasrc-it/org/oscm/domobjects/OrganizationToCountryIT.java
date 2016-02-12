/*******************************************************************************
 *  Copyright FUJITSU LIMITED 2016 
 *******************************************************************************/

package org.oscm.domobjects;

import static org.junit.Assert.assertEquals;

import java.util.List;
import java.util.concurrent.Callable;

import javax.ejb.EJBException;

import org.junit.Assert;
import org.junit.Test;

import org.oscm.domobjects.enums.ModificationType;
import org.oscm.test.ReflectiveCompare;
import org.oscm.test.data.Organizations;
import org.oscm.test.data.SupportedCountries;
import org.oscm.internal.types.exception.NonUniqueBusinessKeyException;

public class OrganizationToCountryIT extends DomainObjectTestBase {

    private Organization org;

    private OrganizationToCountry addedCountry;

    private OrganizationToCountry removedCountry;

    /**
     * <b>Testcase:</b> Create new Organization object with 2 country codes<br>
     * <b>ExpectedResult:</b>
     * <ul>
     * <li>All objects can be retrieved from DB and are identical to provided
     * Organization objects</li>
     * <li>Cascaded OrganizationToCountry objects is also stored</li>
     * <li>A history object is created for each country code stored</li>
     * </ul>
     * 
     * @throws Throwable
     */
    @Test
    public void testAdd() throws Throwable {
        try {
            runTX(new Callable<Void>() {
                public Void call() throws Exception {
                    doTestAdd();
                    return null;
                }
            });
            runTX(new Callable<Void>() {
                public Void call() throws Exception {
                    doTestAddCheck();
                    return null;
                }
            });
        } catch (EJBException e) {
            throw e.getCause();
        }
    }

    /*
     * Create organization with a couple of country codes
     */
    private void doTestAdd() throws NonUniqueBusinessKeyException {

        // create organization
        org = new Organization();
        org.setOrganizationId("OrganizationToCountryTest_testAdd");
        org.setCutOffDay(1);

        // create DE country
        SupportedCountry deCountry = SupportedCountries.findOrCreate(mgr, "DE");
        org.setSupportedCountry(deCountry);

        // create US country
        SupportedCountry usCountry = SupportedCountries.findOrCreate(mgr, "US");
        org.setSupportedCountry(usCountry);

        mgr.persist(org);
    }

    /*
     * Asserts that all created countries are persisted correctly
     */
    private void doTestAddCheck() {
        Organization reloadedOrganization = Organizations.findOrganization(mgr,
                org.getOrganizationId());

        // compare country codes reflectively
        checkSame(org.getOrganizationToCountries(),
                reloadedOrganization.getOrganizationToCountries());

        // check history entries
        List<OrganizationToCountry> orgToCountries = reloadedOrganization
                .getOrganizationToCountries();
        checkAddedHistory(orgToCountries.get(0));
        checkAddedHistory(orgToCountries.get(1));
    }

    /*
     * Assert that two given lists of countries are the same.
     */
    private void checkSame(List<OrganizationToCountry> persisted,
            List<OrganizationToCountry> reloaded) {
        for (int i = 0; i < persisted.size(); i++) {
            Assert.assertTrue(ReflectiveCompare.showDiffs(persisted.get(i),
                    reloaded.get(i)), ReflectiveCompare.compare(
                    persisted.get(i), reloaded.get(i)));
        }
    }

    /**
     * <b>Testcase:</b> Modify the list of supported country codes for an
     * existing organization object <br>
     * <b>ExpectedResult:</b>
     * <ul>
     * <li>Modification is saved to the DB</li>
     * <li>History object created for the country codes</li>
     * </ul>
     * 
     * @throws Throwable
     */
    @Test
    public void testModify() throws Throwable {
        try {
            runTX(new Callable<Void>() {
                public Void call() throws Exception {
                    doTestModifyPrepare();
                    return null;
                }

            });
            runTX(new Callable<Void>() {
                public Void call() throws Exception {
                    doTestModify();
                    return null;
                }

            });
            runTX(new Callable<Void>() {
                public Void call() throws Exception {
                    doTestModifyCheck();
                    return null;
                }

            });
        } catch (EJBException e) {
            throw e.getCause();
        }
    }

    /*
     * Create one organization with one country code for testing
     */
    private void doTestModifyPrepare() throws NonUniqueBusinessKeyException {

        // insert new organization
        org = new Organization();
        org.setOrganizationId("OrganizationToCountryTest_testModify");
        org.setCutOffDay(1);

        // create DE country
        SupportedCountry deCountry = SupportedCountries.findOrCreate(mgr, "DE");
        org.setSupportedCountry(deCountry);

        mgr.persist(org);
    }

    /*
     * Remove the existing country code and add a country code
     */
    private void doTestModify() throws NonUniqueBusinessKeyException {
        org = Organizations.findOrganization(mgr, org.getOrganizationId());

        // remove DE country
        removedCountry = org.getOrganizationToCountries().get(0);
        org.getOrganizationToCountries().remove(removedCountry);
        mgr.remove(removedCountry);

        // add JP country
        SupportedCountry jpCountry = SupportedCountries.findOrCreate(mgr, "JP");
        org.setSupportedCountry(jpCountry);
        addedCountry = org.getOrganizationToCountries().get(0);

    }

    /*
     * Check that modifications have been persisted. Check history entries.
     */
    private void doTestModifyCheck() {
        Organization reloadedOrganization = Organizations.findOrganization(mgr,
                org.getOrganizationId());

        // assert changes of supported countries
        checkSame(org.getOrganizationToCountries(),
                reloadedOrganization.getOrganizationToCountries());

        // assert history
        checkAddedHistory(addedCountry);
        checkRemovedHistory(removedCountry);
    }

    /*
     * check that one history entry was created for an added country code
     */
    private void checkAddedHistory(OrganizationToCountry country) {
        List<DomainHistoryObject<?>> entries = mgr.findHistory(country);
        assertEquals("Only one history entry expected", 1, entries.size());
        checkHistoryEntry(ModificationType.ADD, country, entries.get(0));
    }

    /*
     * check that two history entries have been created for a country code that
     * was added and removed again.
     */
    private void checkRemovedHistory(OrganizationToCountry country) {
        List<DomainHistoryObject<?>> entries = mgr.findHistory(country);
        checkHistoryEntry(ModificationType.ADD, country, entries.get(0));
        checkHistoryEntry(ModificationType.DELETE, country, entries.get(1));
    }

    private void checkHistoryEntry(ModificationType type,
            OrganizationToCountry orgToCountry, DomainHistoryObject<?> history) {
        assertEquals("organizationKey",
                orgToCountry.getOrganization().getKey(),
                ((OrganizationToCountryHistory) history)
                        .getOrganizationObjKey());
        assertEquals("countryKey", orgToCountry.getSupportedCountry().getKey(),
                ((OrganizationToCountryHistory) history)
                        .getSupportedCountryObjKey());
        assertEquals("modType", type, history.getModtype());
        assertEquals("modUser", "guest", history.getModuser());
        assertEquals("OBJID in history different", orgToCountry.getKey(),
                history.getObjKey());
    }

    /**
     * Create supplier and organization. Supplier defined a list of supported
     * countries. The customer chooses a domicile country from the provided list
     * of the supplier.
     * 
     * @throws Throwable
     */
    @Test
    public void testSetDomicileCountry() throws Throwable {
        try {
            runTX(new Callable<Void>() {
                public Void call() throws Exception {
                    doSetDomicileCountry();
                    return null;
                }

            });
            runTX(new Callable<Void>() {
                public Void call() throws Exception {
                    doSetDomicileCountryCheck();
                    return null;
                }

            });
        } catch (EJBException e) {
            throw e.getCause();
        }
    }

    private void doSetDomicileCountry() throws Exception {

        // create supplier that supports DE
        Organization supplier = new Organization();
        supplier.setOrganizationId("supplier");
        SupportedCountry deCountry = SupportedCountries.findOrCreate(mgr, "DE");
        supplier.setSupportedCountry(deCountry);
        supplier.setCutOffDay(1);
        mgr.persist(supplier);

        // create customer and set DE as domicile
        Organization customer = new Organization();
        customer.setOrganizationId("customer");
        customer.setDomicileCountry(deCountry);
        customer.setCutOffDay(1);
        mgr.persist(customer);

    }

    private void doSetDomicileCountryCheck() {
        Organization reloadedCustomer = Organizations.findOrganization(mgr,
                "customer");
        assertEquals("DE", reloadedCustomer.getDomicileCountryCode());

        // check history of organization to country
        SupportedCountry orgToCountryProxy = reloadedCustomer
                .getDomicileCountry();

        // check history of organization
        List<DomainHistoryObject<?>> entries = mgr
                .findHistory(reloadedCustomer);
        OrganizationHistory orgHistory = (OrganizationHistory) entries.get(0);
        assertEquals(orgToCountryProxy.getKey(), orgHistory
                .getDomicileCountryObjKey().longValue());
    }
}
