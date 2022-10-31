package provider

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/hashicorp/terraform-plugin-sdk/v2/meta"
	"github.com/jkroepke/terraform-provider-azure-aks-command/internal/clients"
	"github.com/jkroepke/terraform-provider-azure-aks-command/internal/helpers"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure AzureAksAADTokenProvider satisfies various provider interfaces.
var _ provider.Provider = &AzureAksAADTokenProvider{}
var _ provider.ProviderWithMetadata = &AzureAksAADTokenProvider{}

// AzureAksAADTokenProvider defines the provider implementation.
type AzureAksAADTokenProvider struct {
	// the version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// AzureAksAADTokenProviderModel describes the provider data model.
type AzureAksAADTokenProviderModel struct {
	ClientId                  types.String `tfsdk:"client_id"`
	TenantId                  types.String `tfsdk:"tenant_id"`
	Environment               types.String `tfsdk:"environment"`
	MetadataHost              types.String `tfsdk:"metadata_host"`
	ClientCertificatePath     types.String `tfsdk:"client_certificate_path"`
	ClientCertificatePassword types.String `tfsdk:"client_certificate_password"`
	ClientSecret              types.String `tfsdk:"client_secret"`
	OidcRequestToken          types.String `tfsdk:"oidc_request_token"`
	OidcRequestUrl            types.String `tfsdk:"oidc_request_url"`
	OidcToken                 types.String `tfsdk:"oidc_token"`
	OidcTokenFilePath         types.String `tfsdk:"oidc_token_file_path"`
	UseOidc                   types.Bool   `tfsdk:"use_oidc"`
	UseMsi                    types.Bool   `tfsdk:"use_msi"`
	MsiEndpoint               types.String `tfsdk:"msi_endpoint"`
	PartnerId                 types.String `tfsdk:"partner_id"`
}

func (p *AzureAksAADTokenProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "azure-aks-aad-token"
	resp.Version = p.version
}

func (p *AzureAksAADTokenProvider) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"client_id": {
				Description: "The Client ID which should be used.",
				Optional:    true,
				Type:        types.StringType,
				Computed:    true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					helpers.EnvVarModifier{EnvVarNames: []string{"ARM_CLIENT_ID"}, DefaultValue: ""},
				},
			},
			"tenant_id": {
				Description: "The Tenant ID which should be used.",
				Optional:    true,
				Type:        types.StringType,
				Computed:    true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					helpers.EnvVarModifier{EnvVarNames: []string{"ARM_TENANT_ID"}, DefaultValue: ""},
				},
			},
			"environment": {
				Description: "The Cloud Environment which should be used. Possible values are public, usgovernment, and china. Defaults to public.",
				Optional:    true,
				Type:        types.StringType,
				Computed:    true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					helpers.EnvVarModifier{EnvVarNames: []string{"ARM_ENVIRONMENT"}, DefaultValue: "public"},
				},
			},
			"metadata_host": {
				Description: "The Hostname which should be used for the Azure Metadata Service.",
				Optional:    true,
				Type:        types.StringType,
				Computed:    true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					helpers.EnvVarModifier{EnvVarNames: []string{"ARM_METADATA_HOSTNAME"}, DefaultValue: ""},
				},
			},

			// Client Certificate specific fields
			"client_certificate_path": {
				Description: "The path to the Client Certificate associated with the Service Principal for use when authenticating as a Service Principal using a Client Certificate.",
				Optional:    true,
				Type:        types.StringType,
				Computed:    true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					helpers.EnvVarModifier{EnvVarNames: []string{"ARM_CLIENT_CERTIFICATE_PATH"}, DefaultValue: ""},
				},
			},
			"client_certificate_password": {
				Description: "The password associated with the Client Certificate. For use when authenticating as a Service Principal using a Client Certificate",
				Optional:    true,
				Type:        types.StringType,
				Computed:    true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					helpers.EnvVarModifier{EnvVarNames: []string{"ARM_CLIENT_CERTIFICATE_PASSWORD"}, DefaultValue: ""},
				},
			},

			// Client Secret specific fields
			"client_secret": {
				Description: "The Client Secret which should be used. For use When authenticating as a Service Principal using a Client Secret.",
				Optional:    true,
				Type:        types.StringType,
				Computed:    true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					helpers.EnvVarModifier{EnvVarNames: []string{"ARM_CLIENT_SECRET"}, DefaultValue: ""},
				},
			},

			// OIDC specific fields
			"oidc_request_token": {
				Description: "The bearer token for the request to the OIDC provider. For use when authenticating as a Service Principal using OpenID Connect.",
				Optional:    true,
				Type:        types.StringType,
				Computed:    true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					helpers.EnvVarModifier{EnvVarNames: []string{"ARM_OIDC_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"}, DefaultValue: ""},
				},
			},
			"oidc_request_url": {
				Description: "The URL for the OIDC provider from which to request an ID token. For use when authenticating as a Service Principal using OpenID Connect.",
				Optional:    true,
				Type:        types.StringType,
				Computed:    true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					helpers.EnvVarModifier{EnvVarNames: []string{"ARM_OIDC_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_URL"}, DefaultValue: ""},
				},
			},
			"oidc_token": {
				Description: "The OIDC ID token for use when authenticating as a Service Principal using OpenID Connect.",
				Optional:    true,
				Type:        types.StringType,
				Computed:    true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					helpers.EnvVarModifier{EnvVarNames: []string{"ARM_OIDC_TOKEN"}, DefaultValue: ""},
				},
			},
			"oidc_token_file_path": {
				Description: "The path to a file containing an OIDC ID token for use when authenticating as a Service Principal using OpenID Connect.",
				Optional:    true,
				Type:        types.StringType,
				Computed:    true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					helpers.EnvVarModifier{EnvVarNames: []string{"ARM_OIDC_TOKEN_FILE_PATH"}, DefaultValue: ""},
				},
			},
			"use_oidc": {
				Description: "Allow OpenID Connect to be used for authentication",
				Optional:    true,
				Type:        types.BoolType,
				Computed:    true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					helpers.EnvVarModifier{EnvVarNames: []string{"ARM_USE_OIDC"}, DefaultValue: false},
				},
			},

			// Managed Service Identity specific fields
			"use_msi": {
				Description: "Allowed Managed Service Identity be used for Authentication.",
				Type:        types.BoolType,
				Optional:    true,
				Computed:    true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					helpers.EnvVarModifier{EnvVarNames: []string{"ARM_USE_MSI"}, DefaultValue: false},
				},
			},
			"msi_endpoint": {
				Description: "The path to a custom endpoint for Managed Service Identity - in most circumstances this should be detected automatically. ",
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					helpers.EnvVarModifier{EnvVarNames: []string{"ARM_MSI_ENDPOINT"}, DefaultValue: false},
				},
			},

			// Managed Tracking GUID for User-agent
			"partner_id": {
				Description: "A GUID/UUID that is registered with Microsoft to facilitate partner resource usage attribution.",
				Type:        types.StringType,
				Optional:    true,
				Computed:    true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					helpers.EnvVarModifier{EnvVarNames: []string{"ARM_PARTNER_ID"}, DefaultValue: ""},
				},
			},
		},
	}, nil
}

func (p *AzureAksAADTokenProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data AzureAksAADTokenProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	setEnvIfNotExists("AZURE_CLIENT_ID", data.ClientId.ValueString())
	setEnvIfNotExists("AZURE_CLIENT_SECRET", data.ClientSecret.ValueString())
	setEnvIfNotExists("AZURE_CERTIFICATE_PATH", data.ClientCertificatePath.ValueString())
	setEnvIfNotExists("AZURE_CERTIFICATE_PASSWORD", data.ClientCertificatePassword.ValueString())
	setEnvIfNotExists("AZURE_ENVIRONMENT", data.Environment.ValueString())

	if data.UseMsi.ValueBool() {
		setEnvIfNotExists("MSI_ENDPOINT", data.MsiEndpoint.ValueString())
	} else if data.UseOidc.ValueBool() {
		var token string

		if data.OidcRequestUrl.ValueString() != "" && data.OidcRequestToken.ValueString() != "" {
			var err error

			token, err = helpers.GetOidcTokenFromGithubActions(data.OidcRequestUrl.ValueString(), data.OidcRequestToken.ValueString())
			if err != nil {
				resp.Diagnostics.AddError("Error while request token from GH API", err.Error())
				return
			}
		} else if data.OidcToken.ValueString() != "" {
			token = data.OidcToken.ValueString()
		}

		if token != "" {
			f, err := os.CreateTemp("", "token*")
			if err != nil {
				resp.Diagnostics.AddError("Error while request token from GH API", err.Error())
				return
			}

			_, err = f.WriteString(data.OidcToken.ValueString())
			if err != nil {
				resp.Diagnostics.AddError("Error while request token from GH API", err.Error())
				return
			}

			_ = os.Setenv("AZURE_FEDERATED_TOKEN_FILE", f.Name())

			defer func(name string) {
				_ = os.Remove(name)
			}(f.Name())
		} else {
			_ = os.Setenv("AZURE_FEDERATED_TOKEN_FILE", data.OidcTokenFilePath.ValueString())
		}
	}

	userAgent := buildUserAgent(req.TerraformVersion, p.version, data.PartnerId.ValueString())

	cred, err := helpers.NewAzureCredential(
		&azidentity.DefaultAzureCredentialOptions{
			TenantID: data.TenantId.ValueString(),
			ClientOptions: azcore.ClientOptions{
				Cloud: p.getCloudConfig(data),
				PerCallPolicies: []policy.Policy{
					clients.WithUserAgent(userAgent),
				},
			},
		},
	)

	if err != nil {
		resp.Diagnostics.AddError("Error while request token for AKS", err.Error())
		return
	}

	resp.DataSourceData = cred
}

func (p *AzureAksAADTokenProvider) getCloudConfig(data AzureAksAADTokenProviderModel) cloud.Configuration {
	switch data.Environment.ValueString() {
	case "public":
		return cloud.AzurePublic
	case "usgovernment":
		return cloud.AzureGovernment
	case "china":
		return cloud.AzureChina
	default:
		return cloud.AzurePublic
	}
}

func (p *AzureAksAADTokenProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}

func (p *AzureAksAADTokenProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewTokenDataSource,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &AzureAksAADTokenProvider{
			version: version,
		}
	}
}

func buildUserAgent(terraformVersion string, providerVersion string, partnerID string) string {
	if terraformVersion == "" {
		// Terraform 0.12 introduced this field to the protocol
		// We can therefore assume that if it's missing it's 0.10 or 0.11
		terraformVersion = "0.11+compatible"
	}

	tfUserAgent := fmt.Sprintf("HashiCorp Terraform/%s (+https://www.terraform.io) Terraform Plugin SDK/%s", terraformVersion, meta.SDKVersionString())
	providerUserAgent := fmt.Sprintf("terraform-provider-azure-aks-aad-token/%s", providerVersion)
	userAgent := strings.TrimSpace(fmt.Sprintf("%s %s", tfUserAgent, providerUserAgent))

	// append the CloudShell version to the user agent if it exists
	if azureAgent := os.Getenv("AZURE_HTTP_USER_AGENT"); azureAgent != "" {
		userAgent = fmt.Sprintf("%s %s", userAgent, azureAgent)
	}

	if partnerID != "" {
		userAgent = fmt.Sprintf("%s pid-%s", userAgent, partnerID)
	}
	return userAgent
}

func setEnvIfNotExists(envVarName string, value string) {
	if v := os.Getenv(envVarName); v == "" && value != "" {
		_ = os.Setenv(envVarName, value)
	}
}
