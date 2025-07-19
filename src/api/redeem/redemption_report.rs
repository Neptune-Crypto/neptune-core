use std::path::PathBuf;

use itertools::Itertools;
use rand::distr::Alphanumeric;
use rand::distr::Distribution;
use rand::distr::StandardUniform;
use rand::rng;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use strum::Display;
use strum::EnumString;
use strum::VariantNames;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::api::export::NativeCurrencyAmount;
use crate::api::export::Network;
use crate::api::export::Timestamp;
use crate::models::state::wallet::address::generation_address::GenerationReceivingAddress;

#[derive(Debug, Clone, Copy, Default, EnumString, VariantNames, Display)]
#[strum(serialize_all = "kebab_case", ascii_case_insensitive)]
pub enum RedemptionReportDisplayFormat {
    #[default]
    Readable,
    Detailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedemptionReportEntry {
    amount: NativeCurrencyAmount,
    earliest_release_date: Option<Timestamp>,
    address: GenerationReceivingAddress,
}

impl RedemptionReportEntry {
    fn headings() -> [String; 3] {
        ["amount", "earliest release date", "address"].map(|s| s.to_string())
    }

    fn column_widths(format: RedemptionReportDisplayFormat) -> [usize; 3] {
        let amount_width = usize::max(
            NativeCurrencyAmount::max().display_lossless().len(),
            NativeCurrencyAmount::max().to_nau().to_string().len(),
        );
        let release_date_width = match format {
            RedemptionReportDisplayFormat::Readable => Timestamp::now().standard_format().len(),
            RedemptionReportDisplayFormat::Detailed => BFieldElement::MAX.to_string().len(),
        };
        let random_address = GenerationReceivingAddress::derive_from_seed(rng().random());
        let network = Network::Main;
        let address_width = match format {
            RedemptionReportDisplayFormat::Readable => random_address
                .to_bech32m_abbreviated(network)
                .unwrap()
                .len(),
            RedemptionReportDisplayFormat::Detailed => {
                random_address.to_bech32m(network).unwrap().len()
            }
        };

        let entry_widths = [amount_width, release_date_width, address_width];
        let heading_widths = Self::headings().map(|h| h.len());
        heading_widths
            .into_iter()
            .zip(entry_widths)
            .map(|(l, r)| usize::max(l, r))
            .collect_vec()
            .try_into()
            .unwrap()
    }

    fn render(&self, format: RedemptionReportDisplayFormat, column_widths: [usize; 3]) -> String {
        let amount = match format {
            RedemptionReportDisplayFormat::Readable => self.amount.display_lossless(),
            RedemptionReportDisplayFormat::Detailed => self.amount.to_nau().to_string(),
        };

        let amount_padded = format!("{:>width$}", amount, width = column_widths[0]);

        let earliest_release_date = match (format, self.earliest_release_date) {
            (_, None) => "-".to_string(),
            (RedemptionReportDisplayFormat::Readable, Some(rd)) => rd.standard_format(),
            (RedemptionReportDisplayFormat::Detailed, Some(rd)) => rd.to_millis().to_string(),
        };
        let earliest_release_date_padded =
            format!("{:width$}", earliest_release_date, width = column_widths[1]);

        let network = Network::Main;
        let address = match format {
            RedemptionReportDisplayFormat::Readable => {
                self.address.to_bech32m_abbreviated(network).unwrap()
            }
            RedemptionReportDisplayFormat::Detailed => self.address.to_bech32m(network).unwrap(),
        };
        let address_padded = format!("{:width$}", address, width = column_widths[2]);

        match format {
            RedemptionReportDisplayFormat::Readable => {
                format!(
                    "| {} | {} | {} |\n",
                    amount_padded, earliest_release_date_padded, address_padded
                )
            }
            RedemptionReportDisplayFormat::Detailed => {
                format!(
                    "{} {} {}\n",
                    amount_padded, earliest_release_date_padded, address_padded
                )
            }
        }
    }
}

impl Distribution<RedemptionReportEntry> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> RedemptionReportEntry {
        let amount = NativeCurrencyAmount::from_nau(
            rng.random_range(0_i128..NativeCurrencyAmount::max().to_nau()),
        );
        let earliest_release_date = if rng.random_bool(0.5_f64) {
            None
        } else {
            Some(
                Timestamp(BFieldElement::new(
                    rng.random_range(0_u64..(1000 * 60 * 60 * 24 * 365)),
                )) + Network::Main.launch_date(),
            )
        };
        let address = GenerationReceivingAddress::derive_from_seed(rng.random());

        RedemptionReportEntry {
            amount,
            earliest_release_date,
            address,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedemptionReport {
    invalids: Vec<PathBuf>,
    conflicts: Vec<PathBuf>,
    table: Vec<RedemptionReportEntry>,
}

impl RedemptionReport {
    fn render_header(format: RedemptionReportDisplayFormat) -> String {
        let headings = RedemptionReportEntry::headings();
        let column_widths = RedemptionReportEntry::column_widths(format);
        match format {
            RedemptionReportDisplayFormat::Readable => {
                let total_width = column_widths.into_iter().sum::<usize>()
                    + "| ".len()
                    + 2 * " | ".len()
                    + " |".len();
                format!(
                    "{:-<widtha$}\n| {:width0$} | {:width1$} | {:width2$} |\n{:-<widthb$}\n",
                    "",
                    headings[0],
                    headings[1],
                    headings[2],
                    "",
                    widtha = total_width,
                    width0 = column_widths[0],
                    width1 = column_widths[1],
                    width2 = column_widths[2],
                    widthb = total_width
                )
            }
            RedemptionReportDisplayFormat::Detailed => format!(
                "{:width0$} {:width1$} {:width2$}\n",
                headings[0],
                headings[1],
                headings[2],
                width0 = column_widths[0],
                width1 = column_widths[1],
                width2 = column_widths[2],
            ),
        }
    }

    fn render_body(&self, format: RedemptionReportDisplayFormat) -> String {
        let column_widths = RedemptionReportEntry::column_widths(format);
        let mut s = "".to_string();
        for row in &self.table {
            s = format!("{s}{}", row.render(format, column_widths));
        }
        s
    }

    fn render_footer(&self, format: RedemptionReportDisplayFormat) -> String {
        let column_widths = RedemptionReportEntry::column_widths(format);
        match format {
            RedemptionReportDisplayFormat::Readable => {
                let total_width = column_widths.into_iter().sum::<usize>()
                    + "| ".len()
                    + 2 * " | ".len()
                    + " |".len();
                format!("{:-<width$}\n", "", width = total_width)
            }
            RedemptionReportDisplayFormat::Detailed => "".to_string(),
        }
    }

    fn render_table(&self, format: RedemptionReportDisplayFormat) -> String {
        format!(
            "{}{}{}",
            Self::render_header(format),
            self.render_body(format),
            self.render_footer(format)
        )
    }

    fn render_invalids(&self) -> String {
        if self.invalids.is_empty() {
            "None.".to_string()
        } else {
            let mut s = "".to_string();
            for invalid in &self.invalids {
                s = format!("{s}{}\n", invalid.to_string_lossy());
            }
            s
        }
    }

    fn render_conflicts(&self) -> String {
        if self.conflicts.is_empty() {
            "None.".to_string()
        } else {
            let mut s = "".to_string();
            for conflict in &self.conflicts {
                s = format!("{s}{}\n", conflict.to_string_lossy());
            }
            s
        }
    }

    pub fn render(&self, format: RedemptionReportDisplayFormat) -> String {
        let invalids = format!("# Invalid\n\n{}\n\n", self.render_invalids(),);
        let conflicts = format!("# Conflicts\n\n{}\n\n", self.render_conflicts());
        let table = format!("# Table\n\n{}\n", self.render_table(format));

        let mut s = "".to_string();
        if !self.invalids.is_empty() {
            s = format!("{s}{}", invalids);
        }

        if !self.conflicts.is_empty() {
            s = format!("{s}{}", conflicts);
        }

        format!("{s}{}", table)
    }
}

impl Distribution<RedemptionReport> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> RedemptionReport {
        pub fn random_filename<R: Rng + ?Sized>(rng: &mut R) -> String {
            let len = rng.random_range(40..50);
            let name: String = rng
                .sample_iter(&Alphanumeric)
                .take(len)
                .map(char::from)
                .collect();
            name.to_string()
        }

        let num_invalids = rng.random_range(0..5);
        let invalids = (0..num_invalids)
            .map(|_| random_filename(rng))
            .map(PathBuf::from)
            .collect_vec();

        let num_conflicts = rng.random_range(0..5);
        let conflicts = (0..num_conflicts)
            .map(|_| random_filename(rng))
            .map(PathBuf::from)
            .collect_vec();

        let num_rows = rng.random_range(0..25);
        let table = (0..num_rows)
            .map(|_| rng.random::<RedemptionReportEntry>())
            .collect_vec();

        RedemptionReport {
            invalids,
            conflicts,
            table,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn can_render_random_report() {
        let mut rng = rng();
        let report = rng.random::<RedemptionReport>();
        let format = if rng.random_bool(0.5_f64) {
            RedemptionReportDisplayFormat::Readable
        } else {
            RedemptionReportDisplayFormat::Detailed
        };
        println!("{}", report.render(format)); // no crash
    }
}
