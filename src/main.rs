pub mod work;
use clap::Parser;
use cloud_terrastodon_azure::prelude::Group;
use cloud_terrastodon_azure::prelude::RoleAssignment;
use cloud_terrastodon_azure::prelude::RoleDefinition;
use cloud_terrastodon_azure::prelude::Scope;
use cloud_terrastodon_azure::prelude::User;
use cloud_terrastodon_azure::prelude::fetch_all_role_assignments;
use cloud_terrastodon_azure::prelude::fetch_all_role_definitions;
use cloud_terrastodon_azure::prelude::fetch_all_security_groups;
use cloud_terrastodon_azure::prelude::fetch_all_users;
use itertools::Itertools;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::ops::Deref;
use std::ops::Not;
use std::path::PathBuf;
use tokio::try_join;
use tracing::Level;
use tracing::info;
use tracing::warn;
use work::ParallelFallibleWorkQueue;

#[derive(Parser)]
#[command(name = "admin_account_audit")]
#[command(about = "Audit admin account role assignments in Azure")]
struct Cli {
    /// Output path for the JSON results
    output_path: PathBuf,
    
    /// Clobber the output file if it already exists
    #[arg(long)]
    overwrite_existing: bool,
}

#[derive(Serialize)]
pub struct Discovery {
    pub user: User,
    pub source: Source,
    pub role_assignment: RoleAssignment,
    pub role_definition: RoleDefinition,
}

#[derive(Serialize)]
pub enum Source {
    Direct,
    Group(Group),
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    
    let cli = Cli::parse();
    
    // Check if output file exists and handle overwrite logic
    if cli.output_path.exists() && !cli.overwrite_existing {
        return Err(eyre::eyre!(
            "Output file {:?} already exists. Use --overwrite-existing to overwrite it.",
            cli.output_path
        ));
    }
    
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(Level::INFO.into())
                .from_env_lossy(),
        )
        .with_target(false)
        .without_time()
        .init();

    let (role_assignments, role_definitions, users, groups) = try_join!(
        fetch_all_role_assignments(),
        fetch_all_role_definitions(),
        fetch_all_users(),
        fetch_all_security_groups(),
    )?;
    let non_admin_accounts = users
        .iter()
        .filter_map(|user| {
            if user
                .user_principal_name
                .to_ascii_lowercase()
                .starts_with("admin.")
                .not()
            {
                Some((user.id.deref().clone(), user))
            } else {
                None
            }
        })
        .collect::<HashMap<_, _>>();
    let role_definitions = role_definitions
        .into_iter()
        .map(|role_definition| (role_definition.id.clone(), role_definition))
        .collect::<HashMap<_, _>>();
    let groups = groups
        .into_iter()
        .map(|group| (*group.id.clone(), group))
        .collect::<HashMap<_, _>>();
    let mut groups_to_fetch = Vec::new();

    let mut non_admin_users_with_role_assignments = Vec::new();
    for role_assignment in &role_assignments {
        let Some(role_definition) = role_definitions.get(&role_assignment.role_definition_id)
        else {
            warn!(
                "Role definition {:?} not found for role assignment {:?}",
                role_assignment.role_definition_id, role_assignment.id
            );
            continue;
        };
        if let Some(user) = non_admin_accounts.get(&role_assignment.principal_id) {
            info!(
                "Found role assignment for {:?} - {:?} - {}",
                user.display_name,
                role_definition.display_name,
                role_assignment.scope.expanded_form()
            );
            non_admin_users_with_role_assignments.push(Discovery {
                user: (*user).clone(),
                source: Source::Direct,
                role_assignment: role_assignment.clone(),
                role_definition: role_definition.clone(),
            });
        }
        if let Some(group) = groups.get(&role_assignment.principal_id) {
            info!(
                "Found role assignment for group {:?} - {:?} - {}",
                group.display_name,
                role_definition.display_name,
                role_assignment.scope.expanded_form()
            );
            groups_to_fetch.push((
                group.clone(),
                role_assignment.clone(),
                role_definition.clone(),
            ));
        }
    }
    info!(
        "Found {} role assignments targeting non admin users so far",
        non_admin_accounts.len()
    );
    info!(
        "Found {} role assignments targeting groups so far",
        groups_to_fetch.len()
    );

    info!("Fetching group members...");
    let mut work = ParallelFallibleWorkQueue::new("Fetching group members", 10);
    let mut group_members = HashMap::new();

    for group_id in groups_to_fetch
        .iter()
        .map(|(group, ..)| group.id.clone())
        .unique()
    {
        work.enqueue(async move {
            let members = cloud_terrastodon_azure::prelude::fetch_group_members(group_id).await?;
            Ok((group_id, members))
        });
    }
    for row in work.join().await? {
        let (group_id, members) = row;
        group_members.insert(group_id, members);
    }
    for (group, role_assignment, role_definition) in groups_to_fetch {
        let Some(members) = group_members.get(&group.id) else {
            warn!(
                "No members found for group {} with role assignment {:?}",
                group.id, role_assignment.id
            );
            continue;
        };
        for member in members {
            if let Some(user) = non_admin_accounts.get(&member.id()) {
                info!(
                    "Role assignment for {:?} - {:?} - {}",
                    user.display_name,
                    role_definition.display_name,
                    role_assignment.scope.expanded_form()
                );
                non_admin_users_with_role_assignments.push(Discovery {
                    user: (*user).clone(),
                    source: Source::Group(group.clone()),
                    role_assignment: role_assignment.clone(),
                    role_definition: role_definition.clone(),
                });
            }
        }

    }

    info!(
        "Total role assignments targeting non-admin users found: {} of {}",
        non_admin_users_with_role_assignments.len(),
        role_assignments.len()
    );

    // Write results to JSON file
    let json_output = serde_json::to_string_pretty(&non_admin_users_with_role_assignments)?;
    fs::write(&cli.output_path, json_output)?;
    info!("Results written to {:?}", cli.output_path);

    Ok(())
}
